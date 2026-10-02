// Exercise a compiled binary through real TLS. Certificates and signing keys
// below are isolated test material, never production configuration.
const assert = require('node:assert/strict');
const https = require('node:https');
const http = require('node:http');
const http2 = require('node:http2');
const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');
const { spawn, execFileSync } = require('node:child_process');
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

function solve(challenge, payloadHash) {
  const challengeBytes = Buffer.from(challenge.challenge, 'base64url');
  for (let counter = 0n; ; counter++) {
    const nonce = Buffer.alloc(8);
    nonce.writeBigUInt64LE(counter);
    const digest = hash(Buffer.concat([challengeBytes, nonce, payloadHash]));
    const full = Math.floor(challenge.bits / 8), remainder = challenge.bits % 8;
    if (digest.subarray(0, full).every(byte => byte === 0) &&
        (!remainder || (digest[full] & (255 << (8 - remainder))) === 0)) return b64(nonce);
  }
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
    child = spawn(binary, [], { cwd: resolve('.'), env: { ...process.env,
      HTTP_BIND_ADDR: `127.0.0.1:${httpPort}`, HTTPS_BIND_ADDR: `127.0.0.1:${httpsPort}`,
      PUBLIC_HOST: 'localhost', TLS_CERT_PATH: initial.cert, TLS_KEY_PATH: initial.key,
      SIGNING_KEY: fixture.seed, POW_BITS_CREATE: '8', POW_BITS_CREATE_MAX: '8',
      POW_BITS_VIEW: '8', POW_BITS_VIEW_MAX: '8', RATE_INIT_PER_MIN: '500',
      RATE_CREATE_PER_MIN: '500', RATE_VIEW_PER_MIN: '500',
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
    const ttl = 43200, ttlBytes = Buffer.alloc(8);
    ttlBytes.writeBigUInt64BE(BigInt(ttl));
    const init = (await api('/api/v1/init?scope=create')).body;
    const nonce = solve(init.pow, hash(Buffer.concat([ttlBytes, Buffer.from(blob)])));
    const created = await api('/api/v1/notes', 'POST', { alg: 'aes-256-gcm', ttl, blob,
      view_token: viewToken, challenge: init.pow.challenge, nonce });
    assert.equal(created.status, 200);
    const nid = created.body.nid;
    async function view(token) {
      const init = (await api('/api/v1/init?scope=view')).body;
      return api(`/api/v1/notes/${nid}/view`, 'POST', { challenge: init.pow.challenge,
        nonce: solve(init.pow, hash(Buffer.from('view:' + nid))), view_token: token });
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
