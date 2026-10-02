const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync, mkdtempSync, mkdirSync, writeFileSync, statSync, symlinkSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const fixture = require('./fixtures/signed-response.json');

function frontend() {
  const elements = new Map();
  function eventTarget() {
    const listeners = new Map();
    const target = {
      handlers: {},
      listenerCount: event => listeners.get(event)?.size || 0,
      addEventListener(event, handler) {
        if (!listeners.has(event)) listeners.set(event, new Set());
        listeners.get(event).add(handler);
        target.handlers[event] = async (...args) => {
          for (const listener of [...listeners.get(event)]) await listener(...args);
        };
      },
      removeEventListener(event, handler) { listeners.get(event)?.delete(handler); },
    };
    return target;
  }
  function element(id) {
    const classes = new Set(id.startsWith('s') && id !== 'sCompose' ? ['hidden'] : []);
    if (!elements.has(id)) elements.set(id, {
      ...eventTarget(), value: '', textContent: '', dataset: {}, style: {},
      classList: {
        add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name),
        toggle(name, force) { const add = force === undefined ? !classes.has(name) : force; if (add) classes.add(name); else classes.delete(name); },
      }, querySelectorAll() { return []; },
      replaceChildren() {}, appendChild() {}, setAttribute() {}, focus() {},
    });
    return elements.get(id);
  }
  const storage = new Map();
  const context = {
    window: { SECNOTE_CONFIG: {}, addEventListener() {} },
    location: new URL('https://notes.example/'),
    localStorage: { getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value) },
    document: { ...eventTarget(), getElementById: element, querySelectorAll: () => [], querySelector: () => ({ value: '43200' }),
      createElement: tag => element(tag + elements.size),
      createTextNode: text => ({ textContent: text }), createDocumentFragment: () => ({ appendChild() {} }),
      createTreeWalker: () => ({ nextNode: () => null }) },
    NodeFilter: { SHOW_TEXT: 4 }, navigator: {}, history: { replaceState() {} },
    URL, URLSearchParams, Headers, Response, TextEncoder, TextDecoder, Uint8Array, DataView,
    AbortController, crypto: webcrypto, atob, btoa, setTimeout, clearTimeout,
    requestAnimationFrame() {}, fetch: async () => { throw new Error('unexpected network request'); },
  };
  const source = readFileSync('website/app.js', 'utf8');
  const boundary = source.indexOf("window.addEventListener('popstate'");
  assert.ok(boundary > 0);
  vm.runInNewContext(source.slice(0, boundary) + `
    window.security = { encrypt, decrypt, fromb64u, fetchJson, verifyResponseSignature, parseSharedLink, route,
      saveTrustedApi, getTrustedPubkey, getTrustedApis, showApiConfirmModal, setApiPubKey,
      showApiTrustModal, currentNote: () => ({ nid: curNid, key: curKey }),
      currentPubkey: () => apiPubKeyB64,
      mockTrust: (hooks) => {
        fetchApiPubkey = hooks.fetchApiPubkey;
        showExternalApiWarningModal = hooks.warning;
        showPinnedApiTrustResult = hooks.pinned;
      },
      disableWarmup: () => { startComposeWarmup = () => {}; pingApi = () => {}; },
      disableRoutingNetwork: () => { startComposeWarmup = () => {}; pingApi = () => {}; startPresolveView = () => {}; },
      setCurrentKey: key => { curKey = key; }, currentKey: () => curKey,
      prepareCreate: () => {
        powCache.create = { challenge: 'test', bits: 8, expiresAt: Date.now() / 1000 + 60 };
        apiReachable = true;
        solvePoW = async () => 'test-nonce';
      },
      mockFetchJson: fn => { fetchJson = fn; },
    };
  })();`, context, { filename: 'website/app.js' });
  return { api: context.window.security, context, element, storage };
}

test('AES-GCM roundtrips maximum size and rejects changed ciphertext or key', async () => {
  const { api } = frontend();
  for (const text of ['a'.repeat(32768), 'я'.repeat(16384)]) {
    const encrypted = await api.encrypt(text);
    assert.ok(encrypted.blob.length > 32768);
    assert.equal(await api.decrypt(encrypted.blob, encrypted.keyB64), text);
    const bytes = Buffer.from(encrypted.blob, 'base64url');
    bytes[12] ^= 1;
    await assert.rejects(api.decrypt(bytes.toString('base64url'), encrypted.keyB64));
    await assert.rejects(api.decrypt(encrypted.blob, Buffer.alloc(32).toString('base64url')));
  }
  await assert.rejects(api.encrypt('a'.repeat(32769)), /exceeds/);
});

test('contextual signature accepts shared vector and rejects replay and metadata changes', async () => {
  const { api } = frontend();
  const bytes = new TextEncoder().encode(fixture.body);
  const response = new Response(fixture.body, { status: fixture.status, headers: { 'x-secnote-sig-v2': fixture.signature } });
  await api.verifyResponseSignature(response, bytes, fixture.pubkey, fixture.context);
  for (const [key, value] of Object.entries({ method: 'POST', target: '/api/v1/init', requestId: 'fresh-request', requestHash: 'changed-body' })) {
    await assert.rejects(api.verifyResponseSignature(response, bytes, fixture.pubkey, { ...fixture.context, [key]: value }), /invalid/);
  }
  await assert.rejects(api.verifyResponseSignature(new Response(fixture.body, { status: 410, headers: response.headers }), bytes, fixture.pubkey, fixture.context), /invalid/);
  await assert.rejects(api.verifyResponseSignature(response, new TextEncoder().encode('changed'), fixture.pubkey, fixture.context), /invalid/);
  await assert.rejects(api.verifyResponseSignature(new Response(fixture.body, { headers: { 'x-secnote-sig': fixture.signature } }), bytes, fixture.pubkey, fixture.context), /missing/);
});

test('fetch uses fresh nonce and rejects a previously signed response', async () => {
  const { api, context } = frontend();
  api.setApiPubKey(fixture.pubkey);
  const requests = [];
  context.fetch = async (url, options) => {
    requests.push(options.headers.get('x-secnote-request-id'));
    return new Response(fixture.body, { headers: { 'x-secnote-sig-v2': fixture.signature } });
  };
  await assert.rejects(api.fetchJson('https://notes.example/info'), /invalid/);
  await assert.rejects(api.fetchJson('https://notes.example/info'), /invalid/);
  assert.notEqual(requests[0], requests[1]);
  assert.equal(Buffer.from(requests[0], 'base64url').length, 16);
});

test('an explicit pin cannot be bypassed by a different stored key', async () => {
  const { api } = frontend();
  const stored = Buffer.alloc(32, 8).toString('base64url');
  const pinned = fixture.pubkey;
  api.saveTrustedApi('https://external.example', stored);
  let pinChecked = false;
  api.mockTrust({
    fetchApiPubkey: async () => { throw new Error('stored key must not bypass explicit pin'); },
    warning: async () => true,
    pinned: async (url, key) => { pinChecked = true; assert.equal(key, pinned); return false; },
  });
  assert.equal(await api.showApiConfirmModal('https://external.example', pinned), false);
  assert.equal(pinChecked, true);
  assert.equal(api.getTrustedPubkey('https://external.example'), stored);
});

test('saving same origin settings preserves the previously trusted signing key', async () => {
  const { api, element } = frontend();
  api.saveTrustedApi('https://notes.example', fixture.pubkey);
  api.setApiPubKey(fixture.pubkey);
  api.disableWarmup();
  element('apiInp').value = 'https://notes.example';
  await element('saveSettings').handlers.click();
  assert.equal(api.currentPubkey(), fixture.pubkey);
});

test('manually replacing a key works for an already confirmed external API', async () => {
  const { api, element } = frontend();
  api.disableWarmup();
  element('apiInp').value = 'https://external.example|' + fixture.pubkey;
  await element('saveSettings').handlers.click();
  const replacement = Buffer.alloc(32, 9).toString('base64url');
  element('apiInp').value = 'https://external.example|' + replacement;
  await element('saveSettings').handlers.click();
  assert.equal(api.currentPubkey(), replacement);
  assert.equal(api.getTrustedPubkey('https://external.example'), replacement);
});

test('a shared link with two different explicit pins is rejected', () => {
  const { api } = frontend();
  const url = new URL('https://notes.example');
  url.searchParams.set('p', Buffer.alloc(16, 1).toString('base64url'));
  url.searchParams.set('api', 'https://external.example|' + fixture.pubkey);
  url.searchParams.set('pin', Buffer.alloc(32, 8).toString('base64url'));
  url.hash = fixture.pubkey;
  assert.throws(() => api.parseSharedLink(url.toString()), /conflicting/);
});

test('sending prevents duplicate clicks and discards a response after the API changes', async () => {
  const { api, element } = frontend();
  api.setApiPubKey(fixture.pubkey);
  api.prepareCreate();
  api.disableWarmup();
  element('noteInput').value = 'sensitive message';
  let complete, started;
  const began = new Promise(resolve => { started = resolve; });
  api.mockFetchJson(() => { started(); return new Promise(resolve => { complete = resolve; }); });
  const sending = element('sendBtn').handlers.click();
  await began;
  assert.equal(element('sendBtn').disabled, true);
  await element('sendBtn').handlers.click();
  element('apiInp').value = 'https://external.example|' + fixture.pubkey;
  await element('saveSettings').handlers.click();
  complete({ response: { ok: true }, body: { ok: true, nid: Buffer.alloc(16, 1).toString('base64url') } });
  await sending;
  assert.equal(element('linkUrl').textContent, '');
  assert.equal(element('noteInput').value, 'sensitive message');
});

test('closing a read note removes plaintext from the DOM and drops the key reference', () => {
  const { api, element } = frontend();
  element('noteOutput').value = 'sensitive text';
  api.setCurrentKey('secret');
  element('burnBtn').handlers.click();
  assert.equal(element('noteOutput').value, '');
  assert.equal(api.currentKey(), '');
});

test('canceling a trust dialog removes its handlers and prevents a late click from trusting the key', async () => {
  const { api, element } = frontend();
  const controller = new AbortController();
  const url = 'https://external.example';
  const pending = api.showApiTrustModal({ url, pubkey: fixture.pubkey, signal: controller.signal });
  assert.equal(element('apiTrustAccept').listenerCount('click'), 1);
  controller.abort();
  assert.equal(await pending, false);
  assert.equal(element('apiTrustAccept').listenerCount('click'), 0);
  await element('apiTrustAccept').handlers.click();
  assert.equal(api.getTrustedPubkey(url), null);
  assert.equal(api.currentPubkey(), null);
});

test('a slow previous navigation cannot replace the current note or signing key', async () => {
  const { api, context } = frontend();
  api.disableRoutingNetwork();
  const oldUrl = 'https://old.example';
  const oldKey = Buffer.alloc(32, 8).toString('base64url');
  api.saveTrustedApi(oldUrl, oldKey);
  api.saveTrustedApi('https://notes.example', fixture.pubkey);
  let complete, started;
  const began = new Promise(resolve => { started = resolve; });
  api.mockTrust({
    fetchApiPubkey: () => { started(); return new Promise(resolve => { complete = resolve; }); },
    warning: () => { throw new Error('canceled lookup must not open another dialog'); },
    pinned: () => { throw new Error('unexpected pinned dialog'); },
  });
  const oldNid = Buffer.alloc(16, 1).toString('base64url');
  const currentNid = Buffer.alloc(16, 2).toString('base64url');
  const currentKey = Buffer.alloc(32, 3).toString('base64url');
  context.location = new URL('https://notes.example/?api=' + encodeURIComponent(oldUrl) + '&p=' + oldNid + '#' + oldKey);
  const previous = api.route();
  await began;
  context.location = new URL('https://notes.example/?api=https%3A%2F%2Fnotes.example&p=' + currentNid + '#' + currentKey);
  await api.route();
  complete(oldKey);
  await previous;
  assert.equal(api.currentNote().nid, currentNid);
  assert.equal(api.currentNote().key, currentKey);
  assert.equal(api.currentPubkey(), fixture.pubkey);
});

test('navigating away closes the previous endpoint confirmation without trusting that endpoint', async () => {
  const { api, context, element } = frontend();
  api.disableRoutingNetwork();
  api.saveTrustedApi('https://notes.example', fixture.pubkey);
  context.location = new URL('https://notes.example/?api=https%3A%2F%2Funtrusted.example');
  const previous = api.route();
  assert.equal(element('apiConfirmAccept').listenerCount('click'), 1);
  const nid = Buffer.alloc(16, 4).toString('base64url');
  context.location = new URL('https://notes.example/?api=https%3A%2F%2Fnotes.example&p=' + nid + '#' + fixture.pubkey);
  await api.route();
  await previous;
  assert.equal(element('apiConfirmAccept').listenerCount('click'), 0);
  assert.equal(element('oApiConfirm').classList.contains('hidden'), true);
  await element('apiConfirmAccept').handlers.click();
  assert.equal(api.getTrustedPubkey('https://untrusted.example'), null);
  assert.equal(api.currentNote().nid, nid);
  assert.equal(api.currentPubkey(), fixture.pubkey);
});

test('navigation clears rendered plaintext and share links when leaving a note', async () => {
  const { api, context, element } = frontend();
  api.disableRoutingNetwork();
  element('noteOutput').value = 'sensitive text';
  element('linkUrl').textContent = 'https://notes.example/#secret';
  element('localLinkUrl').textContent = 'file:///index.html#secret';
  api.setCurrentKey('secret');
  context.location = new URL('https://notes.example/');
  await api.route();
  assert.equal(element('noteOutput').value, '');
  assert.equal(element('linkUrl').textContent, '');
  assert.equal(element('localLinkUrl').textContent, '');
  assert.equal(api.currentKey(), '');
});

test('an external cancellation aborts an API fetch while its body is pending', async () => {
  const { api, context } = frontend();
  const controller = new AbortController();
  let began;
  const started = new Promise(resolve => { began = resolve; });
  context.fetch = async (url, options) => {
    began();
    return new Response(new ReadableStream({
      start(stream) {
        options.signal.addEventListener('abort', () => {
          stream.error(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        });
      },
    }));
  };
  const pending = api.fetchJson('https://notes.example/info', { allowUnsigned: true, signal: controller.signal });
  await started;
  controller.abort();
  await assert.rejects(pending, /timed out/);
});

test('trust storage tolerates invalid JSON shapes and base64 decoding requires canonical values', () => {
  const { api, storage } = frontend();
  for (const value of ['null', '[]', '42']) {
    storage.set('sn_trusted', value);
    api.saveTrustedApi('https://notes.example', fixture.pubkey);
    assert.equal(api.getTrustedPubkey('https://notes.example'), fixture.pubkey);
  }
  assert.throws(() => api.fromb64u('Zh', 1), /canonical/);
});

test('service worker caches only canonical public assets and bypasses API and arbitrary paths', async () => {
  const events = {}, fetched = [], cached = [];
  const cache = { put: async (key) => cached.push(key), match: async () => null };
  const context = {
    self: { location: { origin: 'https://notes.example' }, addEventListener: (name, fn) => { events[name] = fn; } },
    URL, Response, caches: { open: async () => cache },
    fetch: async (request) => { fetched.push(typeof request === 'string' ? request : request.url); return new Response('public asset'); },
  };
  vm.runInNewContext(readFileSync('website/sw.js', 'utf8'), context);
  async function request(path) {
    const waits = []; let result;
    events.fetch({ request: { url: 'https://notes.example' + path, method: 'GET', mode: 'navigate' },
      respondWith: promise => { result = promise; }, waitUntil: promise => waits.push(promise) });
    await result; await Promise.all(waits);
  }
  await request('/?p=secret-note-id&pin=public-key');
  assert.deepEqual(fetched, ['https://notes.example/']);
  assert.deepEqual(cached, ['https://notes.example/']);
  await request('/info');
  await request('/api/v1/init?scope=create');
  await request('/private?token=secret');
  assert.equal(cached.length, 1);
});

test('certificate setup creates a private env file and safely preserves existing values', () => {
  const directory = mkdtempSync(join(tmpdir(), 'secnote-setup-'));
  try {
    const certificates = join(directory, 'certs&backup|local');
    mkdirSync(join(certificates, 'example.test'), { recursive: true });
    writeFileSync(join(certificates, 'example.test/fullchain.pem'), 'test certificate');
    writeFileSync(join(certificates, 'example.test/privkey.pem'), 'test key');
    const envFile = join(directory, '.env');
    const env = { ...process.env, ENV_FILE: envFile, LETSENCRYPT_DIR: certificates };
    function setup() {
      const result = spawnSync('bash', [resolve('scripts/1click.sh'), 'example.test', 'admin@example.test'], { env, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
    }
    setup();
    assert.equal(statSync(envFile).mode & 0o777, 0o600);
    assert.ok(readFileSync(envFile, 'utf8').includes('PUBLIC_HOST=example.test'));
    writeFileSync(envFile, 'SIGNING_KEY=test-only-placeholder\nTLS_CERT_PATH=old\nTLS_KEY_PATH=old');
    setup();
    const contents = readFileSync(envFile, 'utf8');
    assert.ok(contents.includes('SIGNING_KEY=test-only-placeholder\n'));
    assert.ok(contents.includes('TLS_CERT_PATH=' + join(certificates, 'example.test/fullchain.pem')));
    assert.ok(contents.includes('TLS_KEY_PATH=' + join(certificates, 'example.test/privkey.pem')));
    const symlink = join(directory, 'linked.env');
    symlinkSync(envFile, symlink);
    const rejected = spawnSync('bash', [resolve('scripts/1click.sh'), 'example.test', 'admin@example.test'], { env: { ...env, ENV_FILE: symlink }, encoding: 'utf8' });
    assert.equal(rejected.status, 1);
    assert.match(rejected.stdout, /symlink/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
