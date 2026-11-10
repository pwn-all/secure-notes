// Argon2id proof-of-work: algorithm vectors, server interoperability fixture and the worker.
// Run with `node --test tests/*.test.cjs`.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');
const fixture = require('./fixtures/pow-argon2id-vector.json');

const hex = bytes => Buffer.from(bytes).toString('hex');
const sha256 = bytes => new Uint8Array(createHash('sha256').update(bytes).digest());
const PARAMS = { m_kib: 256, t: 1, p: 1, tag_bytes: 32, nonce_bytes: 8 };

function loadArgon2(context = {}) {
  const ctx = { TextEncoder, Uint8Array, Uint32Array, ...context };
  ctx.globalThis = ctx;
  vm.runInNewContext(readFileSync('website/argon2.js', 'utf8'), ctx, { filename: 'website/argon2.js' });
  return ctx;
}

test('BLAKE2b matches RFC 7693 and OpenSSL across block boundaries', () => {
  const { SecNoteArgon2 } = loadArgon2();
  assert.equal(hex(SecNoteArgon2.blake2b(new TextEncoder().encode('abc'), 64)),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
  assert.equal(hex(SecNoteArgon2.blake2b(new TextEncoder().encode('abc'), 32)),
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');
  for (const length of [0, 1, 127, 128, 129, 256, 257, 1000]) {
    const data = new Uint8Array(length).map((_, i) => (i * 7 + 3) & 0xff);
    assert.equal(hex(SecNoteArgon2.blake2b(data, 64)), createHash('blake2b512').update(data).digest('hex'), `length ${length}`);
  }
});

test('Argon2id matches the RFC 9106 test vector and the reference implementation vectors', () => {
  const { SecNoteArgon2 } = loadArgon2();
  // RFC 9106 §5.3: m=32 KiB, t=3, p=4, secret K and associated data X.
  const tag = SecNoteArgon2.argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2),
    { m: 32, t: 3, p: 4, tagLength: 32, key: new Uint8Array(8).fill(3), ad: new Uint8Array(12).fill(4) });
  assert.equal(hex(tag), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  // github.com/P-H-C/phc-winner-argon2 src/test.c, Argon2id version 0x13.
  const kats = [
    [2, 256, 1, '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe'],
    [2, 256, 2, '6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037'],
  ];
  for (const [t, m, p, expected] of kats) {
    assert.equal(hex(SecNoteArgon2.argon2id('password', 'somesalt', { m, t, p, tagLength: 32 })), expected, `t=${t} m=${m} p=${p}`);
  }
  if (process.env.SECNOTE_SLOW_TESTS) {
    assert.equal(hex(SecNoteArgon2.argon2id('password', 'somesalt', { m: 65536, t: 1, p: 1, tagLength: 32 })),
      'f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98');
  }
});

test('Argon2id rejects parameters outside the supported range', () => {
  const { SecNoteArgon2 } = loadArgon2();
  assert.throws(() => SecNoteArgon2.argon2id('x', 'short', { m: 256 }), /salt/);
  assert.throws(() => SecNoteArgon2.argon2id('x', 'saltsalt', { m: 4 }), /m must/);
  assert.throws(() => SecNoteArgon2.argon2id('x', 'saltsalt', { m: 1 << 20 }), /m must/);
  assert.throws(() => SecNoteArgon2.argon2id('x', 'saltsalt', { m: 256, t: 0 }), /t must/);
  assert.throws(() => SecNoteArgon2.argon2id('x', 'saltsalt', { m: 256, tagLength: 2 }), /tagLength/);
});

test('exact 64-bit index arithmetic matches BigInt', () => {
  const { SecNoteArgon2 } = loadArgon2();
  const { mulHigh32 } = SecNoteArgon2._internals;
  const samples = [[0xffffffff, 0xffffffff], [0, 0], [1, 0xffffffff], [0x80000000, 0x80000000], [0xffff, 0xffff0000]];
  for (let i = 0; i < 20000; i++) samples.push([Math.floor(Math.random() * 2 ** 32), Math.floor(Math.random() * 2 ** 32)]);
  for (const [x, y] of samples) {
    assert.equal(mulHigh32(x >>> 0, y >>> 0), Number((BigInt(x >>> 0) * BigInt(y >>> 0)) >> 32n));
  }
});

test('proof-of-work construction matches the server interoperability fixture', () => {
  const { SecNoteArgon2 } = loadArgon2();
  const te = new TextEncoder();
  const challenge = Buffer.from(fixture.challenge, 'base64url');
  const ttlBytes = Buffer.alloc(8);
  ttlBytes.writeBigUInt64BE(BigInt(fixture.create.ttl));
  const payloadHash = sha256(Buffer.concat([ttlBytes, Buffer.from(fixture.create.blob)]));
  assert.equal(hex(payloadHash), fixture.payload_hash_hex);
  const salt = sha256(Buffer.concat([Buffer.from(te.encode(fixture.salt_domain)), challenge, Buffer.from(payloadHash)]));
  assert.equal(hex(salt), fixture.salt_hex);
  const opts = { m: fixture.params.m_kib, t: fixture.params.t, p: fixture.params.p, tagLength: fixture.params.tag_bytes };
  for (const c of fixture.cases) {
    assert.equal(hex(SecNoteArgon2.argon2id(new Uint8Array(Buffer.from(c.nonce, 'base64url')), salt, opts)), c.tag_hex);
  }
  const solved = Buffer.from(fixture.solved.nonce, 'base64url');
  assert.equal(solved.length, 8 * fixture.solved.rounds);
  fixture.solved.tags_hex.forEach((expected, i) => {
    const tag = SecNoteArgon2.argon2id(new Uint8Array(solved.subarray(8 * i, 8 * i + 8)), salt, opts);
    assert.equal(hex(tag), expected);
    assert.ok(tag[0] >> (8 - fixture.solved.bits) === 0, 'solution has the required leading zero bits');
  });
});

function loadWorker() {
  const messages = [];
  const ctx = {
    TextEncoder, Uint8Array, Uint32Array, DataView, atob, btoa, crypto: webcrypto,
    postMessage: message => messages.push(message),
    importScripts: name => {
      assert.equal(name, 'argon2.js');
      vm.runInContext(readFileSync('website/argon2.js', 'utf8'), ctx, { filename: 'website/argon2.js' });
    },
  };
  ctx.self = ctx;
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(readFileSync('website/pow-worker.js', 'utf8'), ctx, { filename: 'website/pow-worker.js' });
  return { ctx, messages };
}

async function runWorker(data) {
  const { ctx, messages } = loadWorker();
  await ctx.onmessage({ data });
  return messages;
}

test('worker solves Argon2id challenges with distinct per-round solutions bound to the payload hash', async () => {
  const { SecNoteArgon2 } = loadArgon2();
  const payloadHash = Buffer.from(fixture.payload_hash_hex, 'hex').toString('base64url');
  const messages = await runWorker({ challenge: fixture.challenge, payloadHash, bits: 2, rounds: 3, params: PARAMS });
  const result = messages.at(-1);
  assert.equal(result.ok, true, JSON.stringify(result));
  const nonce = Buffer.from(result.nonce, 'base64url');
  assert.equal(nonce.length, 24);
  const chunks = [nonce.subarray(0, 8), nonce.subarray(8, 16), nonce.subarray(16, 24)].map(hex);
  assert.equal(new Set(chunks).size, 3, 'rounds must be distinct solutions');
  const salt = new Uint8Array(Buffer.from(fixture.salt_hex, 'hex'));
  for (const chunk of chunks) {
    const tag = SecNoteArgon2.argon2id(new Uint8Array(Buffer.from(chunk, 'hex')), salt, { m: 256, t: 1, p: 1, tagLength: 32 });
    assert.ok(tag[0] >> 6 === 0, 'each solution has 2 leading zero bits');
  }
  const progress = messages.filter(m => m.ok === false && !m.fatal);
  assert.ok(progress.some(m => m.found === 3 && m.rounds === 3), 'progress reports count found solutions');
});

test('worker refuses unsafe or legacy parameters instead of guessing', async () => {
  const payloadHash = Buffer.alloc(32, 1).toString('base64url');
  const base = { challenge: fixture.challenge, payloadHash, bits: 1, rounds: 1, params: PARAMS };
  for (const bad of [
    { bits: 13 }, { bits: 0 }, { rounds: 17 }, { rounds: undefined },
    { params: { ...PARAMS, m_kib: 1 << 20 } }, { params: { ...PARAMS, t: 9 } }, { params: { ...PARAMS, tag_bytes: 16 } },
    { payloadHash: 'AAAA' }, { challenge: 'not base64url!' },
  ]) {
    const result = (await runWorker({ ...base, ...bad })).at(-1);
    assert.equal(result.fatal, true, JSON.stringify(bad));
  }
  const legacy = (await runWorker({ challenge: fixture.challenge, bits: 8, mode: 'create', ttl: 43200, blob: 'AAAA' })).at(-1);
  assert.equal(legacy.fatal, true, 'the SHA-256 request shape is not solved');
});
