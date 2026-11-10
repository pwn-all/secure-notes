// Exercise a compiled binary through real TLS. Certificates and signing keys
// below are isolated test material, never production configuration.
const assert = require('node:assert/strict');
const https = require('node:https');
const http = require('node:http');
const http2 = require('node:http2');
const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');
const { spawn, spawnSync, execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve, join } = require('node:path');
const { createHash, randomBytes, createPublicKey, verify, webcrypto } = require('node:crypto');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const hash = bytes => createHash('sha256').update(bytes).digest();

async function unusedPort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

function certificate(directory, suffix) {
  const cert = join(directory, `cert-${suffix}.pem`);
  const key = join(directory, `key-${suffix}.pem`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  return { cert, key };
}

// The frontend's Argon2id implementation, evaluated in this global context the way a
// browser or worker loads it (a vm sandbox would be an order of magnitude slower).
(0, eval)(readFileSync(resolve('website/argon2.js'), 'utf8'));
const { argon2id } = globalThis.SecNoteArgon2;

function hasLeadingZeroBits(digest, bits) {
  const full = Math.floor(bits / 8), remainder = bits % 8;
  return digest.subarray(0, full).every(byte => byte === 0) &&
    (!remainder || (digest[full] & (255 << (8 - remainder))) === 0);
}

// Solves the Argon2id challenge /api/v1/init advertised (docs/pow-spec.md).
function solve(pow, payloadHash) {
  assert.equal(pow.alg, 'argon2id-leading-zero-bits');
  const challengeBytes = Buffer.from(pow.challenge, 'base64url');
  const salt = hash(Buffer.concat([Buffer.from('secnote-pow-argon2id-v1'), challengeBytes, payloadHash]));
  const opts = { m: pow.params.m_kib, t: pow.params.t, p: pow.params.p, tagLength: pow.params.tag_bytes };
  const solutions = [];
  for (let counter = 0n; solutions.length < pow.rounds; counter++) {
    const nonce = Buffer.alloc(8);
    nonce.writeBigUInt64LE(counter);
    if (hasLeadingZeroBits(Buffer.from(argon2id(new Uint8Array(nonce), new Uint8Array(salt), opts)), pow.bits)) {
      solutions.push(nonce);
    }
  }
  return b64(Buffer.concat(solutions));
}

function createPayloadHash(ttl, blob) {
  const ttlBytes = Buffer.alloc(8);
  ttlBytes.writeBigUInt64BE(BigInt(ttl));
  return hash(Buffer.concat([ttlBytes, Buffer.from(blob)]));
}

async function main() {
  const directory = mkdtempSync(join(tmpdir(), 'secnote-runtime-'));
  let child, logs = '';
  try {
    const initial = certificate(directory, 'initial');
    const httpsPort = await unusedPort(), httpPort = await unusedPort();
    let ca = readFileSync(initial.cert);
    const fixture = require('./fixtures/signed-response.json');
    const binaryArg = process.argv.indexOf('--binary');
    const binary = resolve(binaryArg === -1 ? 'target/release/secure_notes' : process.argv[binaryArg + 1]);

    // There is no fallback scheme: legacy settings stop the server instead of being clamped.
    for (const [name, value, message] of [['POW_ALG', 'sha256', /POW_ALG=sha256 is not supported/],
      ['POW_BITS_CREATE', '17', /POW_BITS_CREATE=17 exceeds 12/]]) {
      const refused = spawnSync(binary, [], { cwd: resolve('.'), encoding: 'utf8', timeout: 20000,
        env: { ...process.env, [name]: value, HTTP_BIND_ADDR: '127.0.0.1:0', HTTPS_BIND_ADDR: '127.0.0.1:0',
          TLS_CERT_PATH: initial.cert, TLS_KEY_PATH: initial.key, RUST_LOG: 'secure_notes=info' } });
      assert.notEqual(refused.status, 0, `${name}=${value} must stop the server`);
      assert.match(refused.stdout + refused.stderr, message);
    }
    console.log('PASS: legacy SHA-256 proof-of-work settings are refused at startup');

    child = spawn(binary, [], { cwd: resolve('.'), env: { ...process.env,
      HTTP_BIND_ADDR: `127.0.0.1:${httpPort}`, HTTPS_BIND_ADDR: `127.0.0.1:${httpsPort}`,
      PUBLIC_HOST: 'localhost', TLS_CERT_PATH: initial.cert, TLS_KEY_PATH: initial.key,
      SIGNING_KEY: fixture.seed, POW_BITS_CREATE: '1', POW_BITS_CREATE_MAX: '1',
      POW_BITS_VIEW: '1', POW_BITS_VIEW_MAX: '1', POW_ARGON2_M_KIB: '256', POW_ARGON2_T: '1',
      POW_ROUNDS_CREATE: '3', POW_ROUNDS_VIEW: '2', MAX_FILE_BYTES: '200000',
      RATE_INIT_PER_MIN: '500', RATE_CREATE_PER_MIN: '500', RATE_VIEW_PER_MIN: '500',
      MAX_PLAINTEXT_BYTES: '32768', MAX_BLOB_BYTES: '49152',
      MAX_NOTES: '50000', MAX_NOTE_STORAGE_BYTES: '67108864',
      MAX_ACTIVE_CHALLENGES: '10000', MAX_TRACKING_ENTRIES: '100000',
      MAX_CONCURRENT_API_REQUESTS: '64', CLEANUP_INTERVAL_SECS: '5',
      RUST_LOG: 'secure_notes=info',
    }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => { logs += chunk; });
    child.stderr.on('data', chunk => { logs += chunk; });
    child.on('error', error => { logs += error.message; });

    function request(path, method = 'GET', payload, extraHeaders = {}, plain = false) {
      const body = payload === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(payload));
      const requestId = b64(randomBytes(16));
      return new Promise((resolve, reject) => {
        const transport = plain ? http : https;
        const req = transport.request({ hostname: '127.0.0.1', port: plain ? httpPort : httpsPort,
          path, method, ca, agent: false, timeout: 5000, headers: {
            'x-secnote-request-id': requestId, ...(body.length ? {
              'content-type': 'application/json', 'content-length': body.length,
            } : {}), ...extraHeaders,
          } }, response => {
          const chunks = [];
          response.on('data', chunk => chunks.push(chunk));
          response.on('end', () => resolve({ status: response.statusCode,
            headers: response.headers, bytes: Buffer.concat(chunks), requestId, requestBody: body, path, method }));
        });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('request timeout')));
        req.end(body);
      });
    }
    const publicKey = createPublicKey({ format: 'der', type: 'spki', key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(fixture.pubkey, 'base64url'),
    ]) });
    async function api(path, method, payload) {
      const result = await request(path, method, payload);
      assert.ok(result.headers['x-secnote-sig-v2'], 'signature v2 missing');
      const prefix = `secnote-response-v2\n${result.method}\n${result.path}\n${result.requestId}\n${b64(hash(result.requestBody))}\n${result.status}\n`;
      assert.equal(verify(null, Buffer.concat([Buffer.from(prefix), result.bytes]), publicKey,
        Buffer.from(result.headers['x-secnote-sig-v2'], 'base64url')), true, 'invalid signature');
      result.body = JSON.parse(result.bytes);
      return result;
    }
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { assert.equal((await api('/info')).body.pubkey, fixture.pubkey); ready = true; break; }
      catch { if (child.exitCode !== null) break; await delay(50); }
    }
    assert.ok(ready, 'server did not start: ' + logs);
    console.log('PASS: compiled server starts with real TLS and verifies response signatures');

    const info = (await api('/info')).body;
    assert.equal(info.max_file_bytes, 200000);
    const passport = info.passport;
    assert.ok(passport, 'signed /info carries the instance passport');
    assert.match(passport.binary_sha256, /^[0-9a-f]{64}$/);
    assert.equal(passport.binary_sha256, createHash('sha256').update(readFileSync(binary)).digest('hex'),
      'passport hash matches the binary under test');
    assert.ok(Number.isInteger(passport.uptime_secs) && passport.uptime_secs >= 0);
    assert.equal(passport.ram_only.zeroize_on_drop, true);
    if (process.platform === 'linux') {
      assert.equal(passport.ram_only.dumpable, false);
      assert.equal(passport.ram_only.core_dump_limit_zero, true);
      assert.equal(typeof passport.ram_only.memory_locked, 'boolean');
      assert.equal(typeof passport.ram_only.swap_present, 'boolean');
    }
    assert.ok(logs.includes('Instance passport collected'), 'startup log reports hardening outcome');
    console.log('PASS: instance passport is published, hashes the running binary and reports hardening');

    const home = await request('/');
    assert.equal(home.status, 200);
    for (const header of ['content-security-policy', 'strict-transport-security',
      'x-content-type-options', 'referrer-policy', 'cache-control']) assert.ok(home.headers[header], header);
    const redirect = await request('/?p=test', 'GET', undefined, { host: 'attacker.example' }, true);
    assert.equal(redirect.status, 308);
    assert.equal(redirect.headers.location, `https://localhost:${httpsPort}/?p=test`);
    const preflight = await request('/api/v1/notes', 'OPTIONS', undefined, { origin: 'null',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type,x-secnote-request-id' });
    assert.equal(preflight.headers['access-control-allow-origin'], '*');
    assert.ok(preflight.headers['access-control-allow-headers'].includes('x-secnote-request-id'));
    console.log('PASS: static security headers, fixed redirect host and offline-origin CORS');

    const h2 = http2.connect(`https://localhost:${httpsPort}`, { ca });
    try {
      const [settings] = await once(h2, 'remoteSettings');
      assert.equal(settings.maxConcurrentStreams, 64);
      assert.equal(settings.maxHeaderListSize, 16 * 1024);
      const requestId = b64(randomBytes(16));
      const stream = h2.request({ ':path': '/info', 'x-secnote-request-id': requestId });
      const chunks = [], responsePromise = once(stream, 'response'), endPromise = once(stream, 'end');
      stream.on('data', chunk => chunks.push(chunk));
      stream.end();
      const [headers] = await responsePromise;
      await endPromise;
      assert.equal(headers[':status'], 200);
      const bytes = Buffer.concat(chunks);
      const prefix = `secnote-response-v2\nGET\n/info\n${requestId}\n${b64(hash(Buffer.alloc(0)))}\n200\n`;
      assert.equal(verify(null, Buffer.concat([Buffer.from(prefix), bytes]), publicKey,
        Buffer.from(headers['x-secnote-sig-v2'], 'base64url')), true);
    } finally { h2.close(); await once(h2, 'close'); }
    console.log('PASS: HTTP/2 negotiated limits and signed API response');

    const keyBytes = randomBytes(32), iv = randomBytes(12);
    const key = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const plaintext = 'я'.repeat(16384);
    const ciphertext = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.from(plaintext)));
    const blob = b64(Buffer.concat([iv, ciphertext])), viewToken = b64(hash(keyBytes));
    const ttl = 43200;

    // A repeated single solution is not a proof of several rounds, and it burns the challenge.
    const burned = (await api('/api/v1/init?scope=create')).body;
    const burnedNonce = solve(burned.pow, createPayloadHash(ttl, blob));
    const firstSolution = Buffer.from(burnedNonce, 'base64url').subarray(0, 8);
    const repeated = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob, view_token: viewToken,
      challenge: burned.pow.challenge, nonce: b64(Buffer.concat([firstSolution, firstSolution, firstSolution])) });
    assert.equal(repeated.status, 400);
    assert.equal(repeated.body.error.code, 'invalid_pow');
    const reused = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob, view_token: viewToken,
      challenge: burned.pow.challenge, nonce: burnedNonce });
    assert.equal(reused.status, 400);
    assert.equal(reused.body.error.code, 'invalid_challenge');

    const init = (await api('/api/v1/init?scope=create')).body;
    assert.equal(init.pow.alg, 'argon2id-leading-zero-bits');
    assert.deepEqual(init.pow.params, { m_kib: 256, t: 1, p: 1, tag_bytes: 32, nonce_bytes: 8 });
    assert.equal(init.pow.rounds, 3);
    assert.equal(init.limits.max_file_bytes, 200000);
    assert.equal(init.limits.max_plaintext_bytes, 32768);
    assert.ok(init.limits.max_blob_bytes > 200000 * 4 / 3);
    const nonce = solve(init.pow, createPayloadHash(ttl, blob));
    assert.equal(Buffer.from(nonce, 'base64url').length, 24);
    const created = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob,
      view_token: viewToken, challenge: init.pow.challenge, nonce });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const nid = created.body.nid;
    console.log('PASS: Argon2id proof-of-work solved with the frontend implementation; repeated solution rejected and burned');
    async function view(token, noteId = nid) {
      const init = (await api('/api/v1/init?scope=view')).body;
      assert.equal(init.pow.rounds, 2);
      return api(`/api/v1/notes/${noteId}/view`, 'POST', { challenge: init.pow.challenge,
        nonce: solve(init.pow, hash(Buffer.from('view:' + noteId))), view_token: token });
    }
    assert.equal((await view(b64(randomBytes(32)))).status, 410);
    assert.equal((await api('/info')).body.notes, 1);
    console.log('PASS: maximum UTF-8 note creation and wrong-token burn protection');

    if (process.platform !== 'win32') {
      const replacement = certificate(directory, 'replacement');
      const nextCert = readFileSync(replacement.cert), nextKey = readFileSync(replacement.key);
      writeFileSync(initial.cert, nextCert);
      writeFileSync(initial.key, nextKey, { mode: 0o600 });
      process.kill(child.pid, 'SIGHUP');
      ca = nextCert;
      let reloaded = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        try { assert.equal((await api('/info')).body.notes, 1); reloaded = true; break; }
        catch { await delay(50); }
      }
      assert.ok(reloaded, 'valid TLS reload failed: ' + logs);
      writeFileSync(initial.key, 'invalid test key');
      process.kill(child.pid, 'SIGHUP');
      for (let attempt = 0; attempt < 100 && !logs.includes('TLS certificate reload failed'); attempt++) await delay(25);
      assert.ok(logs.includes('TLS certificate reload failed'), 'invalid reload was not reported');
      assert.equal((await api('/info')).body.notes, 1);
      writeFileSync(initial.key, nextKey, { mode: 0o600 });
      console.log('PASS: live certificate reload preserves notes; invalid reload retains active TLS');
    }

    const read = await view(viewToken);
    assert.equal(read.status, 200);
    const encrypted = Buffer.from(read.body.blob, 'base64url');
    const recovered = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: encrypted.subarray(0, 12) }, key, encrypted.subarray(12));
    assert.equal(Buffer.from(recovered).toString(), plaintext);
    assert.equal((await view(viewToken)).status, 410);
    assert.equal((await api('/info')).body.notes, 0);
    console.log('PASS: decrypt maximum note, burn once, then return signed 410');

    // A ~100 KB encrypted file envelope fits the MAX_FILE_BYTES budget and reads back intact.
    const fileBytes = randomBytes(100000);
    const header = Buffer.from(JSON.stringify({ v: 1, text: 2, files: [{ name: 'a.bin', type: 'application/octet-stream', size: fileBytes.length }] }));
    const headerLength = Buffer.alloc(4);
    headerLength.writeUInt32BE(header.length);
    const envelope = Buffer.concat([Buffer.from([0x00, 0x53, 0x4e, 0x46, 0x01]), headerLength, header, Buffer.from('hi'), fileBytes]);
    const fileIv = randomBytes(12);
    const fileBlob = b64(Buffer.concat([fileIv, Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, key, envelope))]));
    assert.ok(fileBlob.length > 49152);
    const fileInit = (await api('/api/v1/init?scope=create')).body;
    const fileNote = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob: fileBlob,
      view_token: viewToken, challenge: fileInit.pow.challenge, nonce: solve(fileInit.pow, createPayloadHash(ttl, fileBlob)) });
    assert.equal(fileNote.status, 200, JSON.stringify(fileNote.body));
    const fileRead = await view(viewToken, fileNote.body.nid);
    assert.equal(fileRead.status, 200);
    const fileEncrypted = Buffer.from(fileRead.body.blob, 'base64url');
    const fileRecovered = Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: fileEncrypted.subarray(0, 12) }, key, fileEncrypted.subarray(12)));
    assert.ok(fileRecovered.equals(envelope));
    const tooLarge = b64(randomBytes(12 + 16 + 32768 + 16384 + 200000 + 1));
    const tooLargeInit = (await api('/api/v1/init?scope=create')).body;
    const rejected = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob: tooLarge,
      view_token: viewToken, challenge: tooLargeInit.pow.challenge, nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
    assert.equal(rejected.status, 413);
    assert.equal(rejected.body.error.code, 'blob_too_large');
    console.log('PASS: encrypted file envelope within MAX_FILE_BYTES round-trips; larger blob is refused');

    const partial = tls.connect({ host: '127.0.0.1', port: httpsPort, ca });
    await once(partial, 'secureConnect');
    const began = Date.now();
    partial.write('GET /info HTTP/1.1\r\nHost: localhost\r\n');
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { partial.destroy(); reject(new Error('incomplete headers stayed open')); }, 12500);
      partial.on('data', () => {});
      partial.on('error', () => {});
      partial.on('close', () => { clearTimeout(timer); resolve(); });
    });
    assert.ok(Date.now() - began <= 12500);
    console.log('PASS: actual incomplete HTTP headers are closed within deadline');
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise(resolve => {
        const timer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); resolve(); }, 12000);
        child.once('exit', () => { clearTimeout(timer); resolve(); });
      });
    }
    rmSync(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
