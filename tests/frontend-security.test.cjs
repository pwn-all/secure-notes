const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, statSync, symlinkSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const fixture = require('./fixtures/signed-response.json');

const POW = { alg: 'argon2id-leading-zero-bits', bits: 4, rounds: 4, params: { m_kib: 4096, t: 1, p: 1, tag_bytes: 32, nonce_bytes: 8 } };

// A small DOM: enough tree, class, attribute and event behaviour for website/app.js.
function makeDom() {
  const byId = new Map();
  function events(target) {
    const listeners = new Map();
    target.handlers = {};
    target.listenerCount = event => listeners.get(event)?.size || 0;
    target.addEventListener = (event, handler) => {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event).add(handler);
      target.handlers[event] = async (...args) => {
        for (const listener of [...(listeners.get(event) || [])]) await listener(...args);
      };
    };
    target.removeEventListener = (event, handler) => { listeners.get(event)?.delete(handler); };
  }
  class TextNode {
    constructor(text) { this.nodeType = 3; this.parentNode = null; this.nodeValue = String(text); }
    get textContent() { return this.nodeValue; }
    set textContent(value) { this.nodeValue = String(value); }
    remove() { this.parentNode?.removeChild(this); }
  }
  class Element {
    constructor(tag, fragment = false) {
      this.tagName = String(tag).toUpperCase();
      this.nodeType = fragment ? 11 : 1;
      this.isFragment = fragment;
      this.childNodes = [];
      this.parentNode = null;
      this._text = '';
      this.dataset = {};
      this.style = {};
      this.attrs = new Map();
      this.hidden = false;
      this.disabled = false;
      this.value = '';
      this.offsetWidth = 0;
      const classes = new Set();
      this._classes = classes;
      this.classList = {
        add: (...names) => names.forEach(name => classes.add(name)),
        remove: (...names) => names.forEach(name => classes.delete(name)),
        contains: name => classes.has(name),
        toggle(name, force) { const add = force === undefined ? !classes.has(name) : force; if (add) classes.add(name); else classes.delete(name); return add; },
      };
      events(this);
    }
    get className() { return [...this._classes].join(' '); }
    set className(value) { this._classes.clear(); String(value).split(/\s+/).filter(Boolean).forEach(name => this._classes.add(name)); }
    get children() { return this.childNodes.filter(node => node.nodeType === 1); }
    get firstChild() { return this.childNodes[0] || null; }
    get textContent() { return this._text + this.childNodes.map(node => node.textContent).join(''); }
    set textContent(value) { this.childNodes.forEach(node => { node.parentNode = null; }); this.childNodes = []; this._text = String(value ?? ''); }
    set innerHTML(html) { this.content = new Element('#fragment', true); this.content.appendChild(new TextNode(String(html).replace(/<[^>]*>/g, ''))); }
    appendChild(node) {
      if (node.isFragment) { [...node.childNodes].forEach(child => this.appendChild(child)); return node; }
      node.parentNode?.removeChild(node);
      node.parentNode = this;
      this.childNodes.push(node);
      return node;
    }
    append(...nodes) { nodes.forEach(node => this.appendChild(typeof node === 'string' ? new TextNode(node) : node)); }
    removeChild(node) { const i = this.childNodes.indexOf(node); if (i >= 0) this.childNodes.splice(i, 1); node.parentNode = null; return node; }
    remove() { this.parentNode?.removeChild(this); }
    replaceChildren(...nodes) { this.textContent = ''; this.append(...nodes); }
    replaceWith(...nodes) { const parent = this.parentNode; if (!parent) return; const i = parent.childNodes.indexOf(this); parent.removeChild(this); nodes.forEach((node, k) => { node.parentNode = parent; parent.childNodes.splice(i + k, 0, node); }); }
    setAttribute(name, value) { this.attrs.set(name, String(value)); if (name === 'class') this.className = value; if (name === 'id') byId.set(String(value), this); }
    getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
    hasAttribute(name) { return this.attrs.has(name); }
    removeAttribute(name) { this.attrs.delete(name); }
    get attributes() { return [...this.attrs.keys()].map(name => ({ name })); }
    set id(value) { this.setAttribute('id', value); }
    get id() { return this.getAttribute('id') || ''; }
    set title(value) { this.attrs.set('title', String(value)); }
    get title() { return this.getAttribute('title') || ''; }
    descendants() { return this.childNodes.flatMap(node => node.nodeType === 1 ? [node, ...node.descendants()] : []); }
    querySelectorAll(selector) {
      const match = /^\.([\w-]+)$/.exec(selector) || /^([a-z]+)$/i.exec(selector);
      if (!match) return [];
      return this.descendants().filter(node => selector.startsWith('.') ? node.classList.contains(match[1]) : node.tagName === match[1].toUpperCase());
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    contains(node) { return node === this || this.descendants().includes(node); }
    focus() {} blur() {}
    click() { return this.handlers.click?.({ target: this, preventDefault() {} }); }
  }
  function element(id) {
    if (!byId.has(id)) { const el = new Element('div'); el.attrs.set('id', id); byId.set(id, el); }
    return byId.get(id);
  }
  const document = {
    body: new Element('body'),
    documentElement: { dir: 'ltr', lang: 'en' },
    visibilityState: 'visible',
    getElementById: element,
    createElement: tag => new Element(tag),
    createElementNS: (ns, tag) => new Element(tag),
    createTextNode: text => new TextNode(text),
    createDocumentFragment: () => new Element('#fragment', true),
    createTreeWalker: () => ({ nextNode: () => null }),
    querySelectorAll: () => [],
    querySelector: () => ({ value: '43200' }),
  };
  events(document);
  return { document, element };
}

function frontend({ languages = ['en'], fetchImpl } = {}) {
  const { document, element } = makeDom();
  const storage = new Map();
  const context = {
    window: { SECNOTE_CONFIG: {}, addEventListener() {} },
    location: new URL('https://notes.example/'),
    localStorage: { getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value) },
    document,
    Node: { ELEMENT_NODE: 1, TEXT_NODE: 3 }, NodeFilter: { SHOW_TEXT: 4 },
    navigator: { languages, clipboard: { writeText: async () => {} } },
    history: { replaceState() {}, pushState() {} },
    URL, URLSearchParams, Headers, Response, Blob, TextEncoder, TextDecoder, Uint8Array, DataView,
    AbortController, crypto: webcrypto, atob, btoa, setTimeout, clearTimeout,
    requestAnimationFrame() {}, fetch: fetchImpl || (async () => { throw new Error('unexpected network request'); }),
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
      disableWarmup: () => { startComposeWarmup = async () => {}; pingApi = async () => true; },
      disableRoutingNetwork: () => { startComposeWarmup = async () => {}; pingApi = async () => true; startPresolveView = () => {}; },
      setCurrentKey: key => { curKey = key; }, currentKey: () => curKey,
      prepareCreate: () => {
        powCache.create = { challenge: 'A'.repeat(32), alg: '${POW.alg}', bits: 1, rounds: 1,
          params: { m_kib: 256, t: 1, p: 1, tag_bytes: 32, nonce_bytes: 8 }, expiresAt: Date.now() / 1000 + 60 };
        apiReachable = true;
        solvePoW = async () => 'test-nonce';
      },
      mockFetchJson: fn => { fetchJson = fn; },
      updateServerInfo, renderNote, burnNote, renderFaq, renderGate, renderLinkReply, addMessage, loadLang, detectLang,
      parseCommand, validatePowScheme, applyServerLimits, addFiles, cleanFileName, decodeNotePlaintext, t,
      limits: () => ({ maxPlaintextBytes, maxBlobBytes, maxFileBytes }),
      attachmentCount: () => attachments.length,
      chatText: () => $('chatLog').textContent,
      isGateVisible, renderHealth, sharedLinkFromText, cancelGate,
    };
  })();`, context, { filename: 'website/app.js' });
  return { api: context.window.security, context, element, storage };
}

function fakeFile(name, bytes, type = 'application/octet-stream') {
  const data = Uint8Array.from(bytes);
  return { name, type, size: data.length, arrayBuffer: async () => data.slice().buffer };
}

test('AES-GCM roundtrips maximum size and rejects changed ciphertext or key', async () => {
  const { api } = frontend();
  for (const text of ['a'.repeat(32768), 'я'.repeat(16384)]) {
    const encrypted = await api.encrypt(text);
    assert.ok(encrypted.blob.length > 32768);
    assert.equal((await api.decrypt(encrypted.blob, encrypted.keyB64)).text, text);
    const bytes = Buffer.from(encrypted.blob, 'base64url');
    bytes[12] ^= 1;
    await assert.rejects(api.decrypt(bytes.toString('base64url'), encrypted.keyB64));
    await assert.rejects(api.decrypt(encrypted.blob, Buffer.alloc(32).toString('base64url')));
  }
  await assert.rejects(api.encrypt('a'.repeat(32769)), /exceeds/);
});

test('text-only notes stay raw UTF-8 so third-party API clients remain compatible', async () => {
  const { api } = frontend();
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, new TextEncoder().encode('plain text from a CLI')));
  const blob = Buffer.concat([iv, ciphertext]).toString('base64url');
  const note = await api.decrypt(blob, Buffer.from(key).toString('base64url'));
  assert.equal(note.text, 'plain text from a CLI');
  assert.equal(note.files.length, 0);
});

test('file notes are packed into one encrypted envelope within the server file limit', async () => {
  const { api } = frontend();
  api.applyServerLimits({ max_plaintext_bytes: 32768, max_blob_bytes: Math.ceil((28 + 32768 + 16384 + 5000) * 4 / 3), max_file_bytes: 5000, ttls: [43200, 86400] });
  assert.equal(api.limits().maxFileBytes, 5000);
  const png = [0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4];
  const files = [fakeFile('../../etc/pass‮wd.png', png, 'image/png'), fakeFile('notes.txt', [104, 105], 'text/plain; charset=utf-8')];
  const encrypted = await api.encrypt('caption', files);
  const note = await api.decrypt(encrypted.blob, encrypted.keyB64);
  assert.equal(note.text, 'caption');
  assert.equal(note.files.length, 2);
  assert.deepEqual([...note.files[0].data], png);
  assert.equal(note.files[0].type, 'image/png');
  assert.equal(note.files[0].name, '_.._etc_passwd.png', 'path separators and bidi overrides are neutralised');
  assert.equal(note.files[1].type, 'application/octet-stream', 'MIME parameters are not trusted');
  assert.deepEqual([...note.files[1].data], [104, 105]);

  await assert.rejects(api.encrypt('', [fakeFile('big.bin', new Uint8Array(5001))]), /too large/);
  // A truncated or padded envelope never yields files.
  const env = new Uint8Array([0, 0x53, 0x4e, 0x46, 1, 0, 0, 0, 2, 0x7b, 0x7d]);
  assert.throws(() => api.decodeNotePlaintext(env), /malformed/);
});

test('attachments respect the operator switch and the total size limit', () => {
  const { api } = frontend();
  api.addFiles([fakeFile('a.bin', [1])]);
  assert.equal(api.attachmentCount(), 0, 'uploads are disabled until the server allows them');
  assert.match(api.chatText(), /does not accept files/);
  api.applyServerLimits({ max_plaintext_bytes: 32768, max_blob_bytes: Math.ceil((28 + 32768 + 16384 + 10) * 4 / 3), max_file_bytes: 10, ttls: [43200, 86400] });
  api.addFiles([fakeFile('a.bin', new Uint8Array(6)), fakeFile('b.bin', new Uint8Array(6))]);
  assert.equal(api.attachmentCount(), 1);
  assert.match(api.chatText(), /too large/);
  assert.throws(() => api.applyServerLimits({ max_plaintext_bytes: 32768, max_blob_bytes: 49152, max_file_bytes: 2 ** 27 }), /file limit/);
  assert.throws(() => api.applyServerLimits({ max_plaintext_bytes: 32768, max_blob_bytes: 2 ** 30 }), /blob limit/);
  assert.equal(api.cleanFileName('...'), 'file');
  assert.equal(api.cleanFileName('a\u0000b\\c'), 'a_b_c');
});

test('only bounded Argon2id proof-of-work parameters are accepted (no legacy fallback)', () => {
  const { api } = frontend();
  const plain = value => JSON.parse(JSON.stringify(value));
  assert.deepEqual(plain(api.validatePowScheme(POW)), POW);
  assert.throws(() => api.validatePowScheme({ alg: 'sha256-leading-zero-bits', bits: 17, rounds: 1 }), /unsupported/);
  assert.throws(() => api.validatePowScheme({ bits: 17 }), /unsupported/, 'a missing alg is not treated as SHA-256');
  assert.throws(() => api.validatePowScheme({ ...POW, bits: 13 }), /difficulty/);
  assert.throws(() => api.validatePowScheme({ ...POW, rounds: 17 }), /rounds/);
  assert.throws(() => api.validatePowScheme({ ...POW, rounds: undefined }), /rounds/);
  assert.throws(() => api.validatePowScheme({ ...POW, params: { ...POW.params, m_kib: 1 << 20 } }), /memory/);
  assert.throws(() => api.validatePowScheme({ ...POW, params: { ...POW.params, t: 9 } }), /time/);
  assert.throws(() => api.validatePowScheme({ ...POW, params: { ...POW.params, p: 8 } }), /parallelism/);
  assert.throws(() => api.validatePowScheme({ ...POW, params: { ...POW.params, tag_bytes: 16 } }), /unsupported/);
  const source = readFileSync('website/app.js', 'utf8') + readFileSync('website/pow-worker.js', 'utf8');
  assert.doesNotMatch(source, /sha256-leading-zero-bits/);
});

test('slash commands are recognised only for known names', () => {
  const { api } = frontend();
  assert.deepEqual(JSON.parse(JSON.stringify(api.parseCommand(' /FAQ '))), { name: '/faq', arg: '' });
  assert.equal(api.parseCommand('/open https://x.example/?p=a#b').arg, 'https://x.example/?p=a#b');
  assert.equal(api.parseCommand('/etc/passwd: root:x:0:0'), null, 'a secret that starts with a slash is sent as a secret');
  assert.equal(api.parseCommand('see /faq'), null);
});

test('the browser language is used, and /faq answers in that language', async () => {
  const langs = {};
  for (const file of readdirSync('website/langs')) langs[file] = readFileSync(join('website/langs', file), 'utf8');
  const fetchImpl = async url => {
    const name = String(url).replace(/^langs\//, '');
    return langs[name] ? new Response(langs[name], { status: 200 }) : new Response('', { status: 404 });
  };
  const { api } = frontend({ languages: ['ru-RU', 'en'], fetchImpl });
  assert.equal(api.detectLang(), 'ru');
  await api.loadLang(api.detectLang());
  const faq = api.renderFaq();
  const text = api.chatText();
  assert.match(text, /Как работает SecNote/);
  assert.match(text, /1 \/ 7.*Вы пишете секрет/s, 'the explainer starts at scene 1 with a Russian caption');
  faq.player.goTo(2);
  assert.match(api.chatText(), /Argon2id, 4 MB памяти на попытку · решений: 4 · попыток в среднем: ≈ 64/, 'scene 3 states the real PoW parameters');
  faq.player.goTo(6);
  assert.match(api.chatText(), /7 \/ 7.*И её больше нет/s);
  assert.equal(frontend({ languages: ['uk'] }).api.detectLang(), 'ua');
  assert.equal(frontend({ languages: ['xx-YY'] }).api.detectLang(), 'en');
});

test('the greeting steps aside while the composer is in use', async () => {
  const { element } = frontend();
  const input = element('noteInput');
  assert.equal(element('hero').classList.contains('away'), false);
  input.value = 'a';
  await input.handlers.input();
  assert.equal(element('hero').classList.contains('away'), true);
  input.value = '';
  await input.handlers.input();
  assert.equal(element('hero').classList.contains('away'), false);
});

test('every language file has exactly the English keys, placeholders and markup', () => {
  const en = JSON.parse(readFileSync('website/langs/en.json', 'utf8'));
  const tokens = value => (value.match(/\{[a-z_]+\}/g) || []).sort().join(',');
  const tags = value => [...new Set((value.match(/<\/?([a-z]+)[^>]*>/g) || []).map(tag => tag.replace(/[<>/]/g, '').split(' ')[0]))].sort().join(',');
  const files = readdirSync('website/langs').filter(name => name.endsWith('.json'));
  assert.equal(files.length, 12);
  for (const file of files) {
    const lang = JSON.parse(readFileSync(join('website/langs', file), 'utf8'));
    assert.deepEqual(Object.keys(lang), Object.keys(en), file + ' keys');
    for (const [key, value] of Object.entries(en)) {
      assert.ok(lang[key].trim(), file + ' ' + key + ' is empty');
      assert.equal(tokens(lang[key]), tokens(value), file + ' ' + key + ' placeholders');
      if (key !== 'ERR_OPEN_USAGE') assert.equal(tags(lang[key]), tags(value), file + ' ' + key + ' markup');
    }
  }
  // The English dictionary embedded in app.js (used offline) is the same as en.json.
  const source = readFileSync('website/app.js', 'utf8');
  const start = source.indexOf('const BUILTIN_I18N = {');
  const builtin = vm.runInNewContext('(' + source.slice(start + 'const BUILTIN_I18N = '.length, source.indexOf('let currentLangCode')).replace(/;\s*$/, '') + ')');
  assert.deepEqual(JSON.parse(JSON.stringify(builtin.en)), en);
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

test('sending prevents duplicate submits and discards a response after the API changes', async () => {
  const { api, element } = frontend();
  api.setApiPubKey(fixture.pubkey);
  api.prepareCreate();
  api.disableWarmup();
  element('noteInput').value = 'sensitive message';
  let complete, started, calls = 0;
  const began = new Promise(resolve => { started = resolve; });
  api.mockFetchJson(() => { calls++; started(); return new Promise(resolve => { complete = resolve; }); });
  const sending = element('composer').handlers.submit({ preventDefault() {} });
  await began;
  assert.equal(element('sendBtn').disabled, true);
  assert.match(api.chatText(), /sensitive message/, 'the secret appears as the outgoing message');
  element('noteInput').value = 'second';
  await element('composer').handlers.submit({ preventDefault() {} });
  assert.equal(calls, 1, 'a second submit while sending is ignored');
  element('noteInput').value = '';
  element('apiInp').value = 'https://external.example|' + fixture.pubkey;
  await element('saveSettings').handlers.click();
  complete({ response: { ok: true }, body: { ok: true, nid: Buffer.alloc(16, 1).toString('base64url') } });
  await sending;
  assert.doesNotMatch(api.chatText(), /AQEBAQEBAQEBAQEBAQEBAQ|https:\/\//, 'no link is shown for a stale API');
  assert.equal(element('noteInput').value, 'sensitive message', 'the unsent secret goes back into the composer');
});

test('a successful send blurs the secret, shows the typing statuses, then a blurred link reply', async () => {
  const { api, element } = frontend();
  api.setApiPubKey(fixture.pubkey);
  api.prepareCreate();
  api.disableWarmup();
  const nid = Buffer.alloc(16, 1).toString('base64url');
  let statusDuringUpload = '';
  let maskedDuringUpload = false;
  api.mockFetchJson(async () => {
    statusDuringUpload = api.chatText();
    maskedDuringUpload = element('chatLog').children[0].querySelector('.bubble').classList.contains('masked');
    return { response: { ok: true }, body: { ok: true, nid } };
  });
  element('noteInput').value = 'top secret';
  await element('composer').handlers.submit({ preventDefault() {} });
  assert.match(statusDuringUpload, /not a robot/);
  assert.ok(maskedDuringUpload, 'the sent secret is blurred as soon as it appears in the chat');
  const text = api.chatText();
  assert.match(text, /one-time link/);
  assert.match(text, new RegExp('https://notes\\.example/\\?p=' + nid + '&pin=' + fixture.pubkey + '#[A-Za-z0-9_-]{43}'));
  assert.equal(element('noteInput').value, '');
  const secret = element('chatLog').children[0].querySelector('.bubble');
  assert.ok(secret.classList.contains('masked'), 'the sent secret stays blurred until hovered or tapped');
  assert.doesNotMatch(text, /expires in|opens once|id: /, 'no metadata clutter under the link');
  assert.doesNotMatch(text, /click to show|hidden/i, 'no "hidden, click to show" hint');
  const box = element('chatLog').querySelector('.link-box');
  assert.ok(box.classList.contains('masked'), 'the link is blurred until hovered or tapped');
  await secret.click();
  await box.click();
  assert.ok(secret.classList.contains('revealed'), 'a tap shows the secret');
  assert.ok(box.classList.contains('revealed'), 'a tap shows the link');
  await new Promise(resolve => setTimeout(resolve, 3100));
  assert.equal(secret.classList.contains('revealed'), false, 'the secret blurs again after 3 s');
  assert.equal(box.classList.contains('revealed'), false, 'and so does the link');
});

test('a pasted share link opens the note instead of being encrypted as a new secret', async () => {
  const { api, element, context } = frontend();
  api.disableRoutingNetwork();
  api.saveTrustedApi('https://notes.example', fixture.pubkey);
  let pinned = 0;
  api.mockTrust({ fetchApiPubkey: async () => fixture.pubkey, warning: async () => true, pinned: async () => { pinned++; return true; } });
  let fetched = false;
  api.mockFetchJson(async () => { fetched = true; throw new Error('a pasted link must not be sent as a note'); });
  const nid = Buffer.alloc(16, 5).toString('base64url');
  const link = 'https://notes.example/?p=' + nid + '&pin=' + fixture.pubkey + '#' + Buffer.alloc(32, 6).toString('base64url');
  assert.equal(api.sharedLinkFromText('  ' + link + '\n'), link.trim());
  assert.equal(api.sharedLinkFromText('look: ' + link), null, 'text around a link keeps it a secret');
  assert.equal(api.sharedLinkFromText('https://example.com/?p=short#x'), null);
  context.history.pushState = (state, title, url) => { context.location = new URL(url); };
  element('noteInput').value = link;
  await element('composer').handlers.submit({ preventDefault() {} });
  assert.equal(fetched, false);
  assert.equal(pinned, 1, 'the pinned key is still checked');
  assert.equal(api.currentNote().nid, nid);
  assert.equal(api.isGateVisible(), true);
  assert.equal(element('noteInput').value, '');
});

test('after a note from another server the user is offered their own server back', async () => {
  const { api, element, context } = frontend();
  api.disableRoutingNetwork();
  api.saveTrustedApi('https://notes.example', fixture.pubkey);
  const otherKey = Buffer.alloc(32, 9).toString('base64url');
  api.mockTrust({ fetchApiPubkey: async () => otherKey, warning: async () => true, pinned: async (url, key) => { api.setApiPubKey(key); return true; } });
  const nid = Buffer.alloc(16, 7).toString('base64url');
  context.location = new URL('https://notes.example/?api=' + encodeURIComponent('https://other.example|' + otherKey) + '&p=' + nid + '#' + Buffer.alloc(32, 8).toString('base64url'));
  await api.route();
  assert.equal(api.currentPubkey(), otherKey);
  assert.equal(element('serverHost').textContent, 'other.example');
  api.cancelGate();
  assert.match(api.chatText(), /now sent through other\.example/);
  assert.match(api.chatText(), /Switch back to notes\.example/);
  const back = element('chatLog').querySelectorAll('button').find(btn => /Switch back/.test(btn.textContent));
  await back.click();
  assert.equal(element('serverHost').textContent, 'notes.example');
  assert.equal(api.currentPubkey(), fixture.pubkey);
  assert.doesNotMatch(api.chatText(), /Switch back/);
});

test('closing a read note removes plaintext from the DOM and drops the key reference', () => {
  const { api } = frontend();
  api.setCurrentKey('secret');
  const opened = api.renderNote({ text: 'sensitive text', files: [{ name: 'a.txt', type: 'text/plain', size: 3, data: new Uint8Array([1, 2, 3]) }] });
  assert.match(api.chatText(), /sensitive text/);
  const data = opened.note.files[0].data;
  api.burnNote(opened);
  assert.doesNotMatch(api.chatText(), /sensitive text|a\.txt/);
  assert.deepEqual([...data], [0, 0, 0], 'decrypted file bytes are zeroed');
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
  assert.equal(api.isGateVisible(), true);
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
  const { api, context } = frontend();
  api.disableRoutingNetwork();
  api.renderNote({ text: 'sensitive text', files: [] });
  const reply = api.addMessage('bot');
  api.renderLinkReply(reply, { url: 'https://notes.example/?p=x#secret-key', ttl: 43200, nid: 'x', files: [] });
  api.setCurrentKey('secret');
  assert.match(api.chatText(), /sensitive text/);
  context.location = new URL('https://notes.example/');
  await api.route();
  assert.equal(api.chatText(), '');
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

test('settings panel renders the signed instance passport without trusting malformed values', () => {
  const { api, element } = frontend();
  api.updateServerInfo({ ok: true, notes: 3, ram_usage: '1 mb', pubkey: 'k', max_file_bytes: 10 * 1024 * 1024, passport: {
    version: '0.1.0', started_at: 1700000000, uptime_secs: 93784,
    binary_sha256: 'ab'.repeat(32),
    ram_only: { dumpable: false, core_dump_limit_zero: true, memory_locked: false,
      memory_lock_detail: 'RLIMIT_MEMLOCK is finite', swap_present: false, zeroize_on_drop: true },
  } });
  assert.equal(element('infoUptime').textContent, '1d 2h');
  assert.equal(element('infoRamOnly').textContent, 'dumpable:no · coredump:off · mlock:no · swap:no · zeroize:yes');
  assert.equal(element('infoRamOnly').title, 'RLIMIT_MEMLOCK is finite');
  assert.equal(element('infoBinary').textContent, 'sha256:' + 'ab'.repeat(32) + ' · v0.1.0');
  assert.equal(element('infoFiles').textContent, 'up to 10 MB');

  // Non-hex digests, missing flags and absent passports degrade to placeholders.
  api.updateServerInfo({ ok: true, max_file_bytes: 0, passport: { binary_sha256: '<script>', ram_only: { dumpable: 'maybe' }, uptime_secs: -5 } });
  assert.equal(element('infoBinary').textContent, '—');
  assert.equal(element('infoUptime').textContent, '—');
  assert.equal(element('infoRamOnly').textContent, 'dumpable:? · coredump:? · mlock:? · swap:? · zeroize:?');
  assert.equal(element('infoFiles').textContent, 'disabled');
  api.updateServerInfo({ ok: true, notes: 0, ram_usage: '0 mb' });
  assert.equal(element('infoRamOnly').textContent, '—');
  assert.equal(element('infoUptime').textContent, '—');
});

test('settings show the current server as one card and open the address form on demand', async () => {
  const { api, element } = frontend();
  api.setApiPubKey(fixture.pubkey);
  api.disableWarmup();
  await element('cogBtn').handlers.click();
  assert.equal(element('oSettings').classList.contains('hidden'), false);
  assert.equal(element('serverHost').textContent, 'notes.example');
  assert.equal(element('serverBadge').textContent, 'this site');
  assert.match(element('serverMeta').textContent, /6kpsY-…G0iw/, 'a short signing-key fingerprint is shown');
  assert.equal(element('defaultBtn').hidden, true, '"use this site" is hidden when already on this site');
  assert.equal(element('serverForm').hidden, true, 'the address form is closed by default');
  await element('changeServerBtn').handlers.click();
  assert.equal(element('serverForm').hidden, false);
  assert.equal(element('changeServerBtn').getAttribute('aria-expanded'), 'true');
  assert.equal(element('apiInp').value, 'https://notes.example');
  await element('cancelSettings').handlers.click();
  assert.equal(element('serverForm').hidden, true);
  element('apiInp').value = 'https://external.example|' + fixture.pubkey;
  await element('saveSettings').handlers.click();
  assert.equal(element('serverHost').textContent, 'external.example');
  assert.equal(element('serverBadge').textContent, 'external');
  assert.equal(element('defaultBtn').hidden, false);
  assert.equal(element('serverForm').hidden, true, 'connecting closes the form');
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
  await request('/argon2.js');
  assert.equal(cached.at(-1), 'https://notes.example/argon2.js', 'the PoW library is part of the offline shell');
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
