/*
 * SecNote Argon2id — RFC 9106 in plain JavaScript.
 *
 * No WebAssembly, no build step, no third-party code. Runs in the page, in a
 * Web Worker (importScripts) and in Node.js (vm context) alike. Written for the
 * SecNote proof-of-work: short inputs, small memory (a few MiB), many calls.
 *
 * Verified against RFC 9106 §5.3 and the reference test vectors from
 * github.com/P-H-C/phc-winner-argon2 (tests/pow-argon2.test.cjs).
 *
 * 64-bit words are stored as little-endian pairs of uint32 (lo, hi) inside
 * Uint32Array buffers. All arithmetic stays within exact double precision.
 */
(function (root) {
  'use strict';

  const ARGON2_TYPE_ID = 2;
  const ARGON2_VERSION_13 = 0x13;
  const BLOCK_WORDS = 256; // 128 × u64 → 256 × u32
  const SYNC_POINTS = 4;
  const ADDRESSES_IN_BLOCK = 128;
  const TWO32 = 4294967296;

  /* ───────────────────────── BLAKE2b (RFC 7693) ───────────────────────── */

  const BLAKE2B_IV = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
    0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
    0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
  ]);

  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  ];

  // v: Uint32Array(32) working vector, m: Uint32Array(32) message words.
  // Indices a,b,c,d address u64 words; x,y address u64 message words.
  function blake2bG(v, m, a, b, c, d, x, y) {
    let al = v[2 * a], ah = v[2 * a + 1];
    let bl = v[2 * b], bh = v[2 * b + 1];
    let cl = v[2 * c], ch = v[2 * c + 1];
    let dl = v[2 * d], dh = v[2 * d + 1];
    let s, t;

    // a = a + b + m[x]
    s = al + bl + m[2 * x];
    al = s >>> 0;
    ah = (ah + bh + m[2 * x + 1] + Math.floor(s / TWO32)) >>> 0;
    // d = rotr64(d ^ a, 32)
    t = dl ^ al; dl = (dh ^ ah) >>> 0; dh = t >>> 0;
    // c = c + d
    s = cl + dl;
    cl = s >>> 0;
    ch = (ch + dh + Math.floor(s / TWO32)) >>> 0;
    // b = rotr64(b ^ c, 24)
    t = (bl ^ cl) >>> 0; const bh1 = (bh ^ ch) >>> 0;
    bl = ((t >>> 24) | (bh1 << 8)) >>> 0;
    bh = ((bh1 >>> 24) | (t << 8)) >>> 0;
    // a = a + b + m[y]
    s = al + bl + m[2 * y];
    al = s >>> 0;
    ah = (ah + bh + m[2 * y + 1] + Math.floor(s / TWO32)) >>> 0;
    // d = rotr64(d ^ a, 16)
    t = (dl ^ al) >>> 0; const dh1 = (dh ^ ah) >>> 0;
    dl = ((t >>> 16) | (dh1 << 16)) >>> 0;
    dh = ((dh1 >>> 16) | (t << 16)) >>> 0;
    // c = c + d
    s = cl + dl;
    cl = s >>> 0;
    ch = (ch + dh + Math.floor(s / TWO32)) >>> 0;
    // b = rotr64(b ^ c, 63) == rotl64(b ^ c, 1)
    t = (bl ^ cl) >>> 0; const bh2 = (bh ^ ch) >>> 0;
    bl = ((t << 1) | (bh2 >>> 31)) >>> 0;
    bh = ((bh2 << 1) | (t >>> 31)) >>> 0;

    v[2 * a] = al; v[2 * a + 1] = ah;
    v[2 * b] = bl; v[2 * b + 1] = bh;
    v[2 * c] = cl; v[2 * c + 1] = ch;
    v[2 * d] = dl; v[2 * d + 1] = dh;
  }

  // h: Uint32Array(16) state, block: Uint8Array(128), t: bytes hashed so far (<= 2^53), last: boolean
  function blake2bCompress(h, block, tBytes, last) {
    const v = new Uint32Array(32);
    const m = new Uint32Array(32);
    for (let i = 0; i < 32; i++) {
      const o = i * 4;
      m[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) >>> 0;
    }
    v.set(h, 0);
    v.set(BLAKE2B_IV, 16);
    // t0 ^= counter (128-bit counter; we only ever hash < 2^53 bytes)
    v[24] = (v[24] ^ (tBytes >>> 0)) >>> 0;
    v[25] = (v[25] ^ Math.floor(tBytes / TWO32)) >>> 0;
    if (last) {
      v[28] = (v[28] ^ 0xffffffff) >>> 0;
      v[29] = (v[29] ^ 0xffffffff) >>> 0;
    }
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r];
      blake2bG(v, m, 0, 4, 8, 12, s[0], s[1]);
      blake2bG(v, m, 1, 5, 9, 13, s[2], s[3]);
      blake2bG(v, m, 2, 6, 10, 14, s[4], s[5]);
      blake2bG(v, m, 3, 7, 11, 15, s[6], s[7]);
      blake2bG(v, m, 0, 5, 10, 15, s[8], s[9]);
      blake2bG(v, m, 1, 6, 11, 12, s[10], s[11]);
      blake2bG(v, m, 2, 7, 8, 13, s[12], s[13]);
      blake2bG(v, m, 3, 4, 9, 14, s[14], s[15]);
    }
    for (let i = 0; i < 16; i++) h[i] = (h[i] ^ v[i] ^ v[i + 16]) >>> 0;
  }

  // Unkeyed BLAKE2b with 1..64 byte output.
  function blake2b(input, outLen) {
    if (!(input instanceof Uint8Array)) throw new TypeError('blake2b input must be Uint8Array');
    if (!Number.isInteger(outLen) || outLen < 1 || outLen > 64) throw new RangeError('blake2b outLen must be 1..64');
    const h = new Uint32Array(BLAKE2B_IV);
    // parameter block word 0: digest length | key length << 8 | fanout(1) << 16 | depth(1) << 24
    h[0] = (h[0] ^ (0x01010000 | outLen)) >>> 0;

    const block = new Uint8Array(128);
    let offset = 0;
    let hashed = 0;
    const len = input.length;
    // Process all but the final (possibly partial, possibly empty) block.
    while (len - offset > 128) {
      block.set(input.subarray(offset, offset + 128));
      offset += 128;
      hashed += 128;
      blake2bCompress(h, block, hashed, false);
    }
    block.fill(0);
    const rest = len - offset;
    block.set(input.subarray(offset, offset + rest));
    hashed += rest;
    blake2bCompress(h, block, hashed, true);

    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = (h[i >>> 2] >>> ((i & 3) * 8)) & 0xff;
    return out;
  }

  /* ───────────────────── Argon2 helpers (RFC 9106 §3.3) ───────────────────── */

  function le32(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  }

  function concatBytes(parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // Variable-length hash H'^T(X).
  function hPrime(input, outLen) {
    const prefixed = concatBytes([le32(outLen), input]);
    if (outLen <= 64) return blake2b(prefixed, outLen);
    const r = Math.ceil(outLen / 32) - 2;
    const out = new Uint8Array(outLen);
    let v = blake2b(prefixed, 64);
    out.set(v.subarray(0, 32), 0);
    for (let i = 1; i < r; i++) {
      v = blake2b(v, 64);
      out.set(v.subarray(0, 32), i * 32);
    }
    const tail = blake2b(v, outLen - 32 * r);
    out.set(tail, 32 * r);
    return out;
  }

  /* ─────────────────── Compression function G (RFC 9106 §3.5) ─────────────────── */

  // Scratch block R (256 × u32) shared by the permutation functions below.
  const BUF = new Uint32Array(BLOCK_WORDS);

  // GB on four u64 words of BUF addressed by u64 indices (RFC 9106 Figure 19).
  // BlaMka step: X = X + Y + 2·lo32(X)·lo32(Y) (mod 2^64). The low product comes from
  // Math.imul exactly; the double product is within 2^10 of the exact value, so subtracting
  // the exact low half and rounding to the nearest multiple of 2^32 recovers the high half.
  function blamkaGB(a, b, c, d) {
    let Al = BUF[2 * a], Ah = BUF[2 * a + 1];
    let Bl = BUF[2 * b], Bh = BUF[2 * b + 1];
    let Cl = BUF[2 * c], Ch = BUF[2 * c + 1];
    let Dl = BUF[2 * d], Dh = BUF[2 * d + 1];
    let ml, mh, rl, xl, xh;

    // A = A ⊞ B; D = rotr64(D ^ A, 32)
    ml = Math.imul(Al, Bl);
    mh = (((Al >>> 0) * (Bl >>> 0) - (ml >>> 0)) / TWO32 + 0.5) | 0;
    rl = (Al >>> 0) + (Bl >>> 0) + ((ml << 1) >>> 0);
    Ah = (Ah + Bh + ((mh << 1) | (ml >>> 31)) + ((rl / TWO32) | 0)) | 0;
    Al = rl | 0;
    xh = Dh ^ Ah; xl = Dl ^ Al;
    Dh = xl; Dl = xh;

    // C = C ⊞ D; B = rotr64(B ^ C, 24)
    ml = Math.imul(Cl, Dl);
    mh = (((Cl >>> 0) * (Dl >>> 0) - (ml >>> 0)) / TWO32 + 0.5) | 0;
    rl = (Cl >>> 0) + (Dl >>> 0) + ((ml << 1) >>> 0);
    Ch = (Ch + Dh + ((mh << 1) | (ml >>> 31)) + ((rl / TWO32) | 0)) | 0;
    Cl = rl | 0;
    xh = Bh ^ Ch; xl = Bl ^ Cl;
    Bh = (xh >>> 24) | (xl << 8);
    Bl = (xh << 8) | (xl >>> 24);

    // A = A ⊞ B; D = rotr64(D ^ A, 16)
    ml = Math.imul(Al, Bl);
    mh = (((Al >>> 0) * (Bl >>> 0) - (ml >>> 0)) / TWO32 + 0.5) | 0;
    rl = (Al >>> 0) + (Bl >>> 0) + ((ml << 1) >>> 0);
    Ah = (Ah + Bh + ((mh << 1) | (ml >>> 31)) + ((rl / TWO32) | 0)) | 0;
    Al = rl | 0;
    xh = Dh ^ Ah; xl = Dl ^ Al;
    Dh = (xh >>> 16) | (xl << 16);
    Dl = (xh << 16) | (xl >>> 16);

    // C = C ⊞ D; B = rotr64(B ^ C, 63)
    ml = Math.imul(Cl, Dl);
    mh = (((Cl >>> 0) * (Dl >>> 0) - (ml >>> 0)) / TWO32 + 0.5) | 0;
    rl = (Cl >>> 0) + (Dl >>> 0) + ((ml << 1) >>> 0);
    Ch = (Ch + Dh + ((mh << 1) | (ml >>> 31)) + ((rl / TWO32) | 0)) | 0;
    Cl = rl | 0;
    xh = Bh ^ Ch; xl = Bl ^ Cl;
    Bh = (xh << 1) | (xl >>> 31);
    Bl = (xh >>> 31) | (xl << 1);

    BUF[2 * a] = Al; BUF[2 * a + 1] = Ah;
    BUF[2 * b] = Bl; BUF[2 * b + 1] = Bh;
    BUF[2 * c] = Cl; BUF[2 * c + 1] = Ch;
    BUF[2 * d] = Dl; BUF[2 * d + 1] = Dh;
  }

  // Permutation P over 16 u64 words of BUF given by index (RFC 9106 Figure 17/18).
  function blamkaP(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
    blamkaGB(v0, v4, v8, v12);
    blamkaGB(v1, v5, v9, v13);
    blamkaGB(v2, v6, v10, v14);
    blamkaGB(v3, v7, v11, v15);
    blamkaGB(v0, v5, v10, v15);
    blamkaGB(v1, v6, v11, v12);
    blamkaGB(v2, v7, v8, v13);
    blamkaGB(v3, v4, v9, v14);
  }

  function permuteBuf() {
    for (let i = 0; i < 128; i += 16) {
      blamkaP(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
        i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
    }
    for (let i = 0; i < 16; i += 2) {
      blamkaP(i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
        i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
    }
  }

  // mem[next] = G(mem[prev], mem[ref]) [^ mem[next] when withXor]. Offsets are u32-word offsets.
  // R = prev ^ ref is staged into the destination first, so the final fold needs one pass.
  function fillBlock(mem, prevOff, refOff, nextOff, withXor) {
    if (withXor) {
      for (let i = 0; i < BLOCK_WORDS; i++) {
        const r = mem[prevOff + i] ^ mem[refOff + i];
        BUF[i] = r;
        mem[nextOff + i] ^= r;
      }
    } else {
      for (let i = 0; i < BLOCK_WORDS; i++) {
        const r = mem[prevOff + i] ^ mem[refOff + i];
        BUF[i] = r;
        mem[nextOff + i] = r;
      }
    }
    permuteBuf();
    for (let i = 0; i < BLOCK_WORDS; i++) mem[nextOff + i] ^= BUF[i];
  }

  // next = G(0, ref) for address-block generation; `ref` and `next` may be the same array.
  function fillBlockFromZero(ref, next) {
    for (let i = 0; i < BLOCK_WORDS; i++) { BUF[i] = ref[i]; next[i] = ref[i]; }
    permuteBuf();
    for (let i = 0; i < BLOCK_WORDS; i++) next[i] ^= BUF[i];
  }

  /* ──────────────────── Reference block index (RFC 9106 §3.4) ──────────────────── */

  // floor(x * y / 2^32) for 0 <= x,y < 2^32, computed exactly without BigInt.
  function mulHigh32(x, y) {
    const x1 = x >>> 16, x0 = x & 0xffff;
    const t1 = x1 * y;           // < 2^48, exact
    const t0 = x0 * y;           // < 2^48, exact
    const t1lo = t1 % 65536;
    const t1hi = (t1 - t1lo) / 65536;          // floor(t1 / 2^16)
    return t1hi + Math.floor((t1lo * 65536 + t0) / TWO32);
  }

  function indexAlpha(pass, slice, laneLen, segLen, index, j1, sameLane) {
    let area;
    if (pass === 0) {
      if (slice === 0) area = index - 1;
      else if (sameLane) area = slice * segLen + index - 1;
      else area = slice * segLen + (index === 0 ? -1 : 0);
    } else if (sameLane) {
      area = laneLen - segLen + index - 1;
    } else {
      area = laneLen - segLen + (index === 0 ? -1 : 0);
    }
    const x = mulHigh32(j1, j1);                    // J1^2 >> 32
    const y = mulHigh32(area >>> 0, x);             // (|W| * x) >> 32
    const relative = area - 1 - y;
    const start = (pass !== 0 && slice !== SYNC_POINTS - 1) ? (slice + 1) * segLen : 0;
    return (start + relative) % laneLen;
  }

  /* ───────────────────────────── Argon2id ───────────────────────────── */

  const memoryCache = { words: 0, buffer: null };

  function toBytes(value, name) {
    if (value == null) return new Uint8Array(0);
    if (value instanceof Uint8Array) return value;
    if (typeof value === 'string') return new TextEncoder().encode(value);
    throw new TypeError(name + ' must be a Uint8Array or string');
  }

  function checkInt(value, name, min, max) {
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new RangeError(name + ' must be an integer in ' + min + '..' + max);
    }
    return value;
  }

  /**
   * argon2id(password, salt, options) → Uint8Array(tagLength)
   *
   * options:
   *   m          memory in KiB (>= 8·p, default 4096)
   *   t          passes (>= 1, default 1)
   *   p          lanes (>= 1, default 1); lanes are processed sequentially
   *   tagLength  output bytes (4..1024, default 32)
   *   key        optional secret K
   *   ad         optional associated data X
   *   maxMemoryKib  refuse to allocate more than this (default 65536)
   */
  function argon2id(password, salt, options) {
    const opts = options || {};
    const pwd = toBytes(password, 'password');
    const saltBytes = toBytes(salt, 'salt');
    const key = toBytes(opts.key, 'key');
    const ad = toBytes(opts.ad, 'ad');
    const p = checkInt(opts.p == null ? 1 : opts.p, 'p', 1, 0xffffff);
    const t = checkInt(opts.t == null ? 1 : opts.t, 't', 1, 0xffffffff);
    const maxMemoryKib = checkInt(opts.maxMemoryKib == null ? 65536 : opts.maxMemoryKib, 'maxMemoryKib', 8, 0x3fffff);
    const m = checkInt(opts.m == null ? 4096 : opts.m, 'm', 8 * p, maxMemoryKib);
    const tagLength = checkInt(opts.tagLength == null ? 32 : opts.tagLength, 'tagLength', 4, 1024);
    if (saltBytes.length < 8) throw new RangeError('salt must be at least 8 bytes');
    const version = ARGON2_VERSION_13;

    // H0 (RFC 9106 §3.2 step 1)
    const h0 = blake2b(concatBytes([
      le32(p), le32(tagLength), le32(m), le32(t), le32(version), le32(ARGON2_TYPE_ID),
      le32(pwd.length), pwd,
      le32(saltBytes.length), saltBytes,
      le32(key.length), key,
      le32(ad.length), ad,
    ]), 64);

    // Memory layout
    const segLen = Math.floor(m / (SYNC_POINTS * p));
    const laneLen = segLen * SYNC_POINTS;
    const mPrime = laneLen * p;
    const words = mPrime * BLOCK_WORDS;
    if (memoryCache.words !== words) {
      memoryCache.buffer = new Uint32Array(words);
      memoryCache.words = words;
    }
    const mem = memoryCache.buffer;

    // First two blocks of every lane
    for (let lane = 0; lane < p; lane++) {
      for (let col = 0; col < 2; col++) {
        const bytes = hPrime(concatBytes([h0, le32(col), le32(lane)]), 1024);
        const off = (lane * laneLen + col) * BLOCK_WORDS;
        for (let i = 0; i < BLOCK_WORDS; i++) {
          const o = i * 4;
          mem[off + i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
        }
      }
    }

    // Address generation state for the data-independent half of Argon2id
    const inputBlock = new Uint32Array(BLOCK_WORDS);
    const addressBlock = new Uint32Array(BLOCK_WORDS);
    const nextAddresses = () => {
      // 64-bit increment of the counter word 6
      inputBlock[12] = (inputBlock[12] + 1) >>> 0;
      if (inputBlock[12] === 0) inputBlock[13] = (inputBlock[13] + 1) >>> 0;
      fillBlockFromZero(inputBlock, addressBlock);
      fillBlockFromZero(addressBlock, addressBlock);
    };

    for (let pass = 0; pass < t; pass++) {
      for (let slice = 0; slice < SYNC_POINTS; slice++) {
        for (let lane = 0; lane < p; lane++) {
          const dataIndependent = pass === 0 && slice < SYNC_POINTS / 2;
          let start = 0;
          if (dataIndependent) {
            inputBlock.fill(0);
            inputBlock[0] = pass;
            inputBlock[2] = lane;
            inputBlock[4] = slice;
            inputBlock[6] = mPrime >>> 0; inputBlock[7] = Math.floor(mPrime / TWO32);
            inputBlock[8] = t >>> 0; inputBlock[9] = Math.floor(t / TWO32);
            inputBlock[10] = ARGON2_TYPE_ID;
          }
          if (pass === 0 && slice === 0) {
            start = 2;
            if (dataIndependent) nextAddresses();
          }
          let cur = lane * laneLen + slice * segLen + start;
          let prev = (cur % laneLen === 0) ? cur + laneLen - 1 : cur - 1;

          for (let i = start; i < segLen; i++) {
            let j1, j2;
            if (dataIndependent) {
              if (i % ADDRESSES_IN_BLOCK === 0) nextAddresses();
              j1 = addressBlock[2 * (i % ADDRESSES_IN_BLOCK)];
              j2 = addressBlock[2 * (i % ADDRESSES_IN_BLOCK) + 1];
            } else {
              j1 = mem[prev * BLOCK_WORDS];
              j2 = mem[prev * BLOCK_WORDS + 1];
            }
            const refLane = (pass === 0 && slice === 0) ? lane : j2 % p;
            const refIndex = indexAlpha(pass, slice, laneLen, segLen, i, j1, refLane === lane);
            const ref = refLane * laneLen + refIndex;
            fillBlock(mem, prev * BLOCK_WORDS, ref * BLOCK_WORDS, cur * BLOCK_WORDS, pass !== 0);
            prev = cur;
            cur++;
          }
        }
      }
    }

    // Finalization: XOR the last column, then H'^T
    const final = new Uint8Array(1024);
    const acc = new Uint32Array(BLOCK_WORDS);
    for (let lane = 0; lane < p; lane++) {
      const off = (lane * laneLen + laneLen - 1) * BLOCK_WORDS;
      for (let i = 0; i < BLOCK_WORDS; i++) acc[i] = (acc[i] ^ mem[off + i]) >>> 0;
    }
    for (let i = 0; i < BLOCK_WORDS; i++) {
      const w = acc[i];
      final[4 * i] = w & 0xff;
      final[4 * i + 1] = (w >>> 8) & 0xff;
      final[4 * i + 2] = (w >>> 16) & 0xff;
      final[4 * i + 3] = (w >>> 24) & 0xff;
    }
    return hPrime(final, tagLength);
  }

  /** Release the cached memory buffer (e.g. when a worker goes idle). */
  function releaseMemory() {
    memoryCache.buffer = null;
    memoryCache.words = 0;
  }

  root.SecNoteArgon2 = Object.freeze({
    argon2id,
    blake2b,
    hPrime,
    releaseMemory,
    _internals: Object.freeze({ mulHigh32, indexAlpha }),
  });
})(typeof self !== 'undefined' ? self : globalThis);
