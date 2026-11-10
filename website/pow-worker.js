// Proof-of-work solver (docs/pow-spec.md): argon2id-leading-zero-bits, the only scheme the
// server accepts. Runs off the main thread; the page only sees progress and the final nonce.
//
// Input:  { challenge, payloadHash, bits, rounds, params: { m_kib, t, p, tag_bytes, nonce_bytes } }
//         payloadHash is base64url(SHA-256(...)) computed by the page, so a large encrypted
//         blob never has to be copied into the worker.
// Output: { ok: false, progress, found, rounds } while working,
//         { ok: true, nonce } with base64url(rounds × 8 distinct solutions),
//         { ok: false, fatal: true, message } on error.
importScripts('argon2.js');

const te = new TextEncoder();
const NONCE_BYTES = 8;
const ARGON2_SALT_DOMAIN = 'secnote-pow-argon2id-v1';
const MAX_BITS = 12;
const MAX_ROUNDS = 16;
const MAX_M_KIB = 65536;
const MAX_T = 8;
const MAX_P = 4;

function b64urlDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

function leadingZeroBits(bytes, bits) {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;
  for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
  if (rem === 0) return true;
  return (bytes[full] & (0xff << (8 - rem))) === 0;
}

function nonceFromCounter(counter) {
  const n = new Uint8Array(NONCE_BYTES);
  const v = new DataView(n.buffer);
  v.setUint32(0, counter >>> 0, true);
  v.setUint32(4, Math.floor(counter / 0x100000000), true);
  return n;
}

function checkInt(value, min, max, name) {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error('invalid PoW ' + name);
  return value;
}

async function solve(data) {
  const bits = checkInt(data.bits, 1, MAX_BITS, 'difficulty');
  const rounds = checkInt(data.rounds, 1, MAX_ROUNDS, 'rounds');
  const params = data.params || {};
  const p = checkInt(params.p, 1, MAX_P, 'parallelism');
  const m = checkInt(params.m_kib, 8 * p, MAX_M_KIB, 'memory');
  const t = checkInt(params.t, 1, MAX_T, 'time');
  if (params.tag_bytes !== 32 || params.nonce_bytes !== NONCE_BYTES) throw new Error('unsupported PoW parameters');
  const challengeBytes = b64urlDecode(data.challenge);
  const payloadHash = b64urlDecode(data.payloadHash);
  if (challengeBytes.length !== 24 || payloadHash.length !== 32) throw new Error('invalid PoW input');

  // salt = SHA-256(domain ‖ challenge ‖ payload_hash): every evaluation is bound to this
  // challenge and this exact payload. The nonce is the Argon2 password.
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256',
    concat(te.encode(ARGON2_SALT_DOMAIN), challengeBytes, payloadHash)));
  const opts = { m, t, p, tagLength: 32, maxMemoryKib: m };
  const solutions = [];
  let counter = 0;
  try {
    while (solutions.length < rounds) {
      const nonce = nonceFromCounter(counter++);
      const found = leadingZeroBits(SecNoteArgon2.argon2id(nonce, salt, opts), bits);
      if (found) solutions.push(nonce);
      if (found || counter % 8 === 0) postMessage({ ok: false, progress: counter, found: solutions.length, rounds });
    }
  } finally {
    SecNoteArgon2.releaseMemory();
  }
  return concat(...solutions);
}

onmessage = async (event) => {
  try {
    const nonce = await solve(event.data || {});
    postMessage({ ok: true, nonce: b64urlEncode(nonce) });
  } catch (e) {
    postMessage({ ok: false, fatal: true, message: String(e && e.message ? e.message : e) });
  }
};
