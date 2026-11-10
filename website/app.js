(function () {
'use strict';

/* ══════════════════════════════════════════════════════
   SecNote — chat client.
   Crypto, signature checks, key pinning and PoW live here; the page is a
   chat: the composer sends a secret, the service "types" while the browser
   proves it is not a robot (Argon2id PoW) and replies with a one-time link.
   ══════════════════════════════════════════════════════ */

/* ── Helpers & constants ── */
const $ = id => document.getElementById(id);
const RUNTIME_CONFIG = window.SECNOTE_CONFIG || {};
const LOCAL_DEV_API = 'http://localhost';
const FALLBACK_DEFAULT_API = /^https?:$/.test(location.protocol) ? location.origin : LOCAL_DEV_API;
const ENABLE_MODEL_CONTEXT_TOOLS = RUNTIME_CONFIG.enableModelContextTools === true;
const DEFAULT_API = initialDefaultApi();
const DEFAULT_API_LABEL = String(RUNTIME_CONFIG.defaultApiLabel || 'Native API');
const DEFAULT_API_PUBKEY = typeof RUNTIME_CONFIG.defaultApiPubKey === 'string' ? (RUNTIME_CONFIG.defaultApiPubKey || null) : null;
const LS_KEY = 'sn_api';
const LS_TRUSTED_KEY = 'sn_trusted';
const LS_TTL_KEY = 'sn_ttl';
const POW_REFRESH_SKEW_MS = 5000;
// The only proof-of-work scheme the server accepts (docs/pow-spec.md). The server picks the
// difficulty; the client only refuses parameters that would be unsafe to run on this device.
const POW_ALG = 'argon2id-leading-zero-bits';
const POW_ARGON2_SALT_DOMAIN = 'secnote-pow-argon2id-v1';
const MAX_POW_BITS = 12;
const MAX_POW_ROUNDS = 16;
const MAX_POW_ARGON2_M_KIB = 65536;
const MAX_POW_ARGON2_T = 8;
const MAX_POW_ARGON2_P = 4;
const POW_NONCE_BYTES = 8;
const DEFAULT_MAX_PLAINTEXT_BYTES = 32768;
const DEFAULT_MAX_BLOB_BYTES = 48 * 1024;
// File notes: the operator allows up to MAX_FILE_BYTES (≤ 64 MiB). Files and text are packed
// into one envelope and encrypted together, so the server only ever sees the total size.
const MAX_FILE_BYTES_CAP = 64 * 1024 * 1024;
const FILE_ENVELOPE_OVERHEAD_BYTES = 16384;
const FILE_ENVELOPE_MAGIC = [0x00, 0x53, 0x4e, 0x46, 0x01]; // "\0SNF" v1
const FILE_ENVELOPE_PREFIX_BYTES = FILE_ENVELOPE_MAGIC.length + 4;
const MAX_FILES = 20;
const MAX_PREVIEW_BYTES = 8 * 1024 * 1024;
const PREVIEW_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
const DEFAULT_RESPONSE_BYTES = 64 * 1024;
const AES_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const ABSOLUTE_MAX_BLOB_BYTES = b64urlEncodedLen(AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES +
  DEFAULT_MAX_PLAINTEXT_BYTES + FILE_ENVELOPE_OVERHEAD_BYTES + MAX_FILE_BYTES_CAP);
const NID_RE = /^[A-Za-z0-9_-]{22}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const PUBKEY_RE = KEY_RE;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{32}$/;
const MIN_HUMAN_STATUS_MS = 700;
const MIN_LINK_STATUS_MS = 450;
const LINK_REVEAL_MS = 3000;
const HEALTH_INTERVAL_MS = 60000;
const SVG_NS = 'http://www.w3.org/2000/svg';
const te = new TextEncoder();
const td = new TextDecoder();

/* ── State ── */
const { url: _initUrl, pubkeyB64: _initPubkey } = initialApiConfig();
let apiUrl = _initUrl;
let apiPubKeyB64 = _initPubkey;
let apiVerifyKey = null;
let curNid = '';
let curKey = '';
const powCache = { create: null, view: null };
const powInitPromises = { create: null, view: null };
let powContextVersion = 0;
let presolvedViewNonce = null;
let presolveViewPromise = null;
let presolveViewState = null;
let viewRefreshTimer = null;
let apiReachable = false;
let apiCheckSeq = 0;
let composeWarmupSeq = 0;
let maxPlaintextBytes = DEFAULT_MAX_PLAINTEXT_BYTES;
let maxBlobBytes = DEFAULT_MAX_BLOB_BYTES;
let maxFileBytes = 0;
let confirmedApiUrl = null;
let createInFlight = false;
let viewInFlight = false;
let apiConfigController = null;
let attachments = [];
let attachSeq = 0;
let messageCount = 0;
let gate = null;
const openedNotes = new Set();
const objectUrls = new Set();
let healthState = 'checking';
let apiLatencyMs = null;
let cmdMenuItems = [];
let cmdMenuIndex = 0;
let lastCreatePow = null;
const explainers = new Set();

/* ══════════════════════════════════════════════════════
   i18n
   ══════════════════════════════════════════════════════ */
const LS_LANG_KEY = 'sn_lang';
const RTL_LANGS = new Set(['ar', 'ur']);
const SUPPORTED_LANGS = new Set(['en', 'de', 'es', 'fr', 'pt', 'ru', 'ua', 'ar', 'bn', 'cn', 'hi', 'ur']);
// English is complete here so the page works offline (file://) and when a language file is
// missing. Other languages carry only the "typing" statuses; the rest comes from langs/*.json.
const BUILTIN_I18N = {
  en: {
    HEALTH_CHECKING: 'connecting…',
    HEALTH_OK: 'online',
    HEALTH_ERR: 'offline',
    HEALTH_NOKEY: 'unsigned',
    HEALTH_TITLE: 'Server: {host} — {state}',
    HERO_TITLE: 'What secret do you want to share?',
    HERO_SUB: 'It is encrypted in your browser, can be read exactly once, and then it is gone. Type <code>/faq</code> to see how it works.',
    COMPOSER_LABEL: 'Secret message',
    COMPOSER_PH: 'Write a secret…',
    COMPOSER_HINT: 'End-to-end encrypted · burns after reading',
    ATTACH: 'Attach files',
    SEND: 'Send',
    PP_LINK: 'privacy & terms',
    PP_CLOSE: '× close',
    PP_ACCEPT: 'I understand & close',
    DROP_TITLE: 'Drop files to encrypt and attach',
    DROP_SUB: 'up to {limit} in total',
    DROP_DISABLED: 'This server does not accept files',
    REMOVE_FILE: 'Remove {name}',
    TTL_SHORT_12: '12h',
    TTL_SHORT_24: '24h',
    TTL_12: '12 hours',
    TTL_24: '24 hours',
    SETTINGS_TITLE: 'Settings',
    SETTINGS_CLOSE: 'Close',
    SETTINGS_LANG: 'Language',
    SETTINGS_TTL: 'Link lifetime',
    SETTINGS_API_LABEL: 'Server',
    SETTINGS_API_HINT: 'Where encrypted notes are stored. Use this site or your own self-hosted instance.',
    SERVER_THIS_SITE: 'this site',
    SERVER_EXTERNAL: 'external',
    SERVER_CHANGE: 'Change server',
    SERVER_CONNECT: 'Connect',
    SERVER_USE_SITE: 'Use this site',
    SERVER_INPUT_HINT: 'HTTPS address of a SecNote server, for example <code>https://notes.example</code>. Append <code>|key</code> to pin its signing key.',
    SERVER_KEY: 'key {key}',
    SERVER_LATENCY: '{ms} ms',
    SERVER_SWITCH_NOTICE: 'New notes are now sent through {host}.',
    SERVER_SWITCH_BACK: 'Switch back to {host}',
    SETTINGS_CANCEL: 'Cancel',
    SETTINGS_CHECKING: 'checking…',
    SETTINGS_REACHABLE: 'reachable',
    SETTINGS_UNREACHABLE: 'unreachable',
    SETTINGS_API_INVALID: 'The server must use HTTPS (or HTTP on localhost).',
    SETTINGS_KEY_INVALID: 'The public key must be a base64url Ed25519 key.',
    SETTINGS_INFO: 'Server info',
    INFO_NOTES: 'notes',
    INFO_RAM: 'RAM',
    INFO_FILES: 'files',
    INFO_UPTIME: 'uptime',
    INFO_BINARY: 'binary',
    INFO_PUBKEY: 'public key',
    FILES_OFF: 'disabled',
    FILES_UP_TO: 'up to {limit}',
    LINK_SOURCE: 'source code',
    LINK_LOCAL: 'download for offline use',
    STATUS_CHECKING: 'Checking that you are not a robot…',
    STATUS_HUMAN: 'You are not a robot',
    STATUS_LINK: 'Handing you the link…',
    STATUS_OPENING: 'Opening the note…',
    LINK_READY: 'Done. Here is your one-time link:',
    LINK_COPY: 'Copy link',
    LINK_COPIED: 'Copied',
    LINK_COPY_FAILED: 'Copy failed — select the link manually',
    LINK_QR: 'QR code',
    LINK_QR_HIDE: 'Hide QR',
    LINK_QR_FAILED: 'Could not draw the QR code',
    LINK_LOCAL_COPY: 'Open with this local copy (this device only):',
    SENT_HIDDEN: 'hidden · click to show',
    GATE_TITLE: 'Someone sent you a one-time secret.',
    GATE_WARN: 'Opening it destroys it on the server immediately — it can be read only once.',
    GATE_REVEAL: 'Read and destroy',
    GATE_CANCEL: 'Not now',
    GATE_CANCELLED: 'The note stays sealed. Open the link again when you are ready.',
    NOTE_TITLE: 'Here is your note:',
    NOTE_COPY: 'Copy text',
    NOTE_BURN: 'Burn now',
    NOTE_DESTROYED: 'It has been destroyed on the server and lives only on this page until you burn it or close the tab.',
    NOTE_BURNED: 'Burned. Nothing is left on this page or on the server.',
    FILE_DOWNLOAD: 'Download',
    BURNED_TITLE: 'This note is already gone.',
    BURNED_SUB: 'It was read, burned or has expired. Each note opens only once.',
    ERR_GENERIC: 'Something went wrong: {message}',
    ERR_UNREACHABLE: 'The server is unreachable. Check your connection or the server in settings.',
    ERR_TEXT_TOO_LARGE: 'The text is too long: {size} of {limit}.',
    ERR_TOO_LARGE: 'The note is too large for this server.',
    ERR_FILES_DISABLED: 'This server does not accept files — only text.',
    ERR_FILES_TOO_LARGE: 'Attachments are too large: {size} of {limit}.',
    ERR_FILES_TOO_MANY: 'Too many files: at most {count}.',
    ERR_FILE_READ: 'Could not read {name}.',
    ERR_RATE: 'Too many requests. Try again in {seconds} s.',
    ERR_BANNED: 'Too many failed checks from your network. Try again in {seconds} s.',
    ERR_BUSY: 'The server is busy. Try again in a moment.',
    ERR_EXPIRED: 'The check took too long. Try again.',
    ERR_LINK_PARAMS: 'The link contains an invalid server address or public key.',
    ERR_UNTRUSTED: 'The server public key was not trusted, so the note was not opened.',
    ERR_MALFORMED: 'The note could not be decrypted — the link may be damaged.',
    ERR_OPEN_USAGE: 'Usage: /open <link>',
    RETRY: 'Try again',
    HELP_TITLE: 'Commands',
    CMD_FAQ: 'how the service works',
    CMD_HELP: 'all commands',
    CMD_CLEAR: 'clear this conversation from the screen',
    CMD_OPEN: 'open a link you received',
    HELP_LINK: 'Paste a full SecNote link — from this or another server — and press Enter to open it.',
    HELP_KEYS: '<b>Enter</b> sends, <b>Shift+Enter</b> adds a new line. Drag files onto the page to attach them (when the server allows files).',
    FAQ_TITLE: 'How SecNote works',
    EX_PLAY: 'Play',
    EX_PAUSE: 'Pause',
    EX_REPLAY: 'Replay',
    EX_STEP: 'Step {n}',
    EX_S1_T: 'You write a secret',
    EX_S1_D: 'Plain text exists only inside this browser tab.',
    EX_S2_T: 'Your browser locks it with a brand-new key',
    EX_S2_D: 'AES-256-GCM in WebCrypto · random 256-bit key · 96-bit IV · integrity tag',
    EX_S3_T: 'It proves it is not a spam robot',
    EX_S3_D: 'Argon2id with {mem} per try · {rounds} solutions ≈ {tries} tries · tied to SHA-256(ttl ‖ ciphertext)',
    EX_S4_T: 'Only the locked box goes to the server',
    EX_S4_D: 'Kept in RAM only: ciphertext + SHA-256(view token) · every reply is signed with Ed25519',
    EX_S5_T: 'The key travels inside the link, after #',
    EX_S5_D: 'Browsers never send the #fragment to servers · ?p= is a random 128-bit id',
    EX_S6_T: 'Your friend opens it — exactly once',
    EX_S6_D: 'Atomic read-and-delete · view token = SHA-256(key) · decrypted only on their device',
    EX_S7_T: 'Then it is gone for good',
    EX_S7_D: 'A second open gets 410 Gone · unread notes expire in 12 or 24 h · a restart wipes the RAM',
    EX_FILES: 'Attachments up to {limit} travel inside the same locked box.',
    FAQ_FOOT: 'Type <code>/help</code> to see all commands.',
  },
  /*BUILTIN_STATUSES_BEGIN*/
  de: { STATUS_CHECKING: 'Wir prüfen, ob Sie kein Roboter sind…', STATUS_HUMAN: 'Sie sind kein Roboter', STATUS_LINK: 'Hier kommt Ihr Link…', STATUS_OPENING: 'Wir öffnen die Notiz…' },
  es: { STATUS_CHECKING: 'Comprobando que no es un robot…', STATUS_HUMAN: 'Usted no es un robot', STATUS_LINK: 'Entregándole el enlace…', STATUS_OPENING: 'Abriendo la nota…' },
  fr: { STATUS_CHECKING: 'Nous vérifions que vous n\'êtes pas un robot…', STATUS_HUMAN: 'Vous n\'êtes pas un robot', STATUS_LINK: 'Nous vous remettons le lien…', STATUS_OPENING: 'Ouverture de la note…' },
  pt: { STATUS_CHECKING: 'Verificando que você não é um robô…', STATUS_HUMAN: 'Você não é um robô', STATUS_LINK: 'Entregando o seu link…', STATUS_OPENING: 'Abrindo a nota…' },
  ru: { STATUS_CHECKING: 'Проверяем, что Вы не робот…', STATUS_HUMAN: 'Вы не робот', STATUS_LINK: 'Отдаём Вам ссылку…', STATUS_OPENING: 'Открываем записку…' },
  ua: { STATUS_CHECKING: 'Перевіряємо, що Ви не робот…', STATUS_HUMAN: 'Ви не робот', STATUS_LINK: 'Передаємо Вам посилання…', STATUS_OPENING: 'Відкриваємо нотатку…' },
  ar: { STATUS_CHECKING: 'نتحقق من أنك لست روبوتًا…', STATUS_HUMAN: 'أنت لست روبوتًا', STATUS_LINK: 'نسلّمك الرابط…', STATUS_OPENING: 'نفتح الملاحظة…' },
  bn: { STATUS_CHECKING: 'আপনি রোবট নন, তা যাচাই করা হচ্ছে…', STATUS_HUMAN: 'আপনি রোবট নন', STATUS_LINK: 'আপনাকে লিংক দেওয়া হচ্ছে…', STATUS_OPENING: 'নোট খোলা হচ্ছে…' },
  cn: { STATUS_CHECKING: '正在确认您不是机器人…', STATUS_HUMAN: '您不是机器人', STATUS_LINK: '正在把链接交给您…', STATUS_OPENING: '正在打开便签…' },
  hi: { STATUS_CHECKING: 'जाँच रहे हैं कि आप रोबोट नहीं हैं…', STATUS_HUMAN: 'आप रोबोट नहीं हैं', STATUS_LINK: 'आपको लिंक दे रहे हैं…', STATUS_OPENING: 'नोट खोल रहे हैं…' },
  ur: { STATUS_CHECKING: 'جانچ رہے ہیں کہ آپ روبوٹ نہیں ہیں…', STATUS_HUMAN: 'آپ روبوٹ نہیں ہیں', STATUS_LINK: 'آپ کو لنک دے رہے ہیں…', STATUS_OPENING: 'نوٹ کھول رہے ہیں…' },
  /*BUILTIN_STATUSES_END*/
};
let currentLangCode = 'en';
let langStrings = {};
let enStrings = null;
let langLoadSeq = 0;

function normalizeLangCode(code) {
  const value = String(code || '').toLowerCase();
  return SUPPORTED_LANGS.has(value) ? value : 'en';
}

// Explicit choice first, then the browser languages, then English.
function detectLang() {
  const stored = storageGet(LS_LANG_KEY, '');
  if (stored && SUPPORTED_LANGS.has(stored)) return stored;
  const aliases = { uk: 'ua', zh: 'cn', be: 'ru', kk: 'ru' };
  const preferred = (typeof navigator !== 'undefined' && (navigator.languages || [navigator.language])) || [];
  for (const raw of preferred) {
    const base = String(raw || '').toLowerCase().split('-')[0];
    const code = aliases[base] || base;
    if (SUPPORTED_LANGS.has(code)) return code;
  }
  return 'en';
}

function sanitizeLangMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out = {};
  Object.entries(value).forEach(([key, val]) => {
    if (typeof key === 'string' && typeof val === 'string') out[key] = val.slice(0, 5000);
  });
  return out;
}

async function fetchLangFile(code) {
  const res = await fetch('langs/' + encodeURIComponent(code) + '.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
  return res.ok ? sanitizeLangMap(await res.json()) : {};
}

async function ensureEnStrings() {
  if (enStrings !== null) return;
  try { enStrings = await fetchLangFile('en'); } catch { enStrings = {}; }
}

async function loadLang(code, { persist = false } = {}) {
  code = normalizeLangCode(code);
  const seq = ++langLoadSeq;
  await ensureEnStrings();
  if (seq !== langLoadSeq) return;
  let strings = {};
  if (code !== 'en') {
    try { strings = await fetchLangFile(code); } catch { strings = {}; }
  }
  if (seq !== langLoadSeq) return;
  currentLangCode = code;
  langStrings = strings;
  if (persist) storageSet(LS_LANG_KEY, code);
  const select = $('langSelect');
  if (select) select.value = code;
  document.documentElement.dir = RTL_LANGS.has(code) ? 'rtl' : 'ltr';
  const langMap = { ua: 'uk', cn: 'zh' };
  document.documentElement.lang = langMap[code] || code;
  applyLang();
}

const SAFE_I18N_TAGS = new Set(['b', 'strong', 'em', 'i', 'br', 'code', 'span']);
function sanitizedI18nFragment(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String(html || '');
  (function clean(node) {
    Array.from(node.childNodes || []).forEach(child => {
      if (child.nodeType === Node.ELEMENT_NODE) {
        const tag = child.tagName.toLowerCase();
        if (!SAFE_I18N_TAGS.has(tag)) {
          child.replaceWith(...child.childNodes);
          clean(node);
          return;
        }
        Array.from(child.attributes).forEach(attr => child.removeAttribute(attr.name));
        clean(child);
      } else if (child.nodeType !== Node.TEXT_NODE) {
        child.remove();
      }
    });
  })(tpl.content);
  return tpl.content;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function rawString(key) {
  return (
    (langStrings && langStrings[key]) ||
    (BUILTIN_I18N[currentLangCode] && BUILTIN_I18N[currentLangCode][key]) ||
    (enStrings && enStrings[key]) ||
    BUILTIN_I18N.en[key] ||
    key
  );
}

function formatString(template, vars, escape) {
  if (!vars) return template;
  return template.replace(/\{([a-z_]+)\}/g, (match, name) => {
    if (!Object.prototype.hasOwnProperty.call(vars, name)) return match;
    return escape ? escapeHtml(vars[name]) : String(vars[name]);
  });
}

function t(key, vars) {
  return formatString(rawString(key), vars || null, false);
}

function i18nFragment(key, vars) {
  return sanitizedI18nFragment(formatString(rawString(key), vars || null, true));
}

function readI18nVars(el) {
  try { return el.dataset.i18nVars ? JSON.parse(el.dataset.i18nVars) : null; } catch { return null; }
}

// Translatable nodes remember their key (and variables), so a language switch re-renders
// everything on the page, including chat messages that already exist.
function setText(el, key, vars) {
  el.dataset.i18n = key;
  if (vars) el.dataset.i18nVars = JSON.stringify(vars); else delete el.dataset.i18nVars;
  el.textContent = t(key, vars);
  return el;
}

function setHtml(el, key, vars) {
  el.dataset.i18nHtml = key;
  if (vars) el.dataset.i18nVars = JSON.stringify(vars); else delete el.dataset.i18nVars;
  el.replaceChildren(i18nFragment(key, vars));
  return el;
}

function applyLang() {
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n, readI18nVars(el)); });
  document.querySelectorAll('[data-i18n-html]').forEach(el => { el.replaceChildren(i18nFragment(el.dataset.i18nHtml, readI18nVars(el))); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-aria]').forEach(el => {
    el.setAttribute('aria-label', t(el.dataset.i18nAria));
    el.setAttribute('title', t(el.dataset.i18nAria));
  });
  updateTtlChip();
  renderHealth();
  updateDropZoneText();
}

/* ══════════════════════════════════════════════════════
   API configuration & trust store
   ══════════════════════════════════════════════════════ */
function storageGet(key, fallback = '') {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage can be disabled in private or hardened browser modes.
  }
}

function parseApiUrl(raw, fallback = DEFAULT_API) {
  let value = String(raw || '').trim();
  if (!value) value = fallback || '';
  if (!value) throw new Error('empty API URL');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = 'https://' + value;
  return new URL(value);
}

function normalizeApiUrl(raw, fallback = DEFAULT_API) {
  const u = parseApiUrl(raw, fallback);
  u.username = '';
  u.password = '';
  u.pathname = '/';
  u.search = '';
  u.hash = '';
  return u.origin.replace(/\/+$/, '');
}

function parseApiConfig(raw) {
  const s = String(raw || '');
  const pipe = s.indexOf('|');
  if (pipe === -1) return { urlStr: s, pubkeyB64: null };
  return { urlStr: s.slice(0, pipe), pubkeyB64: s.slice(pipe + 1) || null };
}

function apiConfigString(url, pubkeyB64) {
  return pubkeyB64 ? url + '|' + pubkeyB64 : url;
}

function normalizePubkeyB64(value) {
  return typeof value === 'string' && PUBKEY_RE.test(value) ? value : null;
}

function getTrustedApis() {
  try {
    const value = JSON.parse(storageGet(LS_TRUSTED_KEY, '{}'));
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch { return {}; }
}
function getTrustedPubkey(url) {
  const map = getTrustedApis();
  const key = normalizeApiUrl(url);
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
}
function saveTrustedApi(url, pubkey) {
  const normalizedPubkey = normalizePubkeyB64(pubkey);
  if (!normalizedPubkey) return;
  const map = getTrustedApis();
  map[normalizeApiUrl(url)] = normalizedPubkey;
  try { localStorage.setItem(LS_TRUSTED_KEY, JSON.stringify(map)); } catch {}
}

async function fetchApiPubkey(baseUrl, verifyPubkeyB64 = null, signal = null) {
  const expectedPubkey = normalizePubkeyB64(verifyPubkeyB64);
  try {
    const { response, body } = await fetchJson(
      new URL('/info', baseUrl + '/').toString(),
      {
        headers: { Accept: 'application/json' },
        allowUnsigned: !expectedPubkey,
        verifyPubkeyB64: expectedPubkey,
        signal,
      },
      4000
    );
    if (!response.ok || !body?.ok) return null;
    return normalizePubkeyB64(body.pubkey);
  } catch { return null; }
}

function isLoopbackHostname(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host === '[::1]' || host === '::1') return true;
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const octets = match.slice(1).map(Number);
  return octets[0] === 127 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
}

function isSafeApiTransport(raw) {
  try {
    const u = parseApiUrl(raw, '');
    if (u.username || u.password) return false;
    if (u.pathname && u.pathname !== '/') return false;
    if (u.search || u.hash) return false;
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && isLoopbackHostname(u.hostname);
  } catch {
    return false;
  }
}

function initialDefaultApi() {
  const configured = RUNTIME_CONFIG.defaultApiUrl;
  if (configured && isSafeApiTransport(configured)) return normalizeApiUrl(configured, FALLBACK_DEFAULT_API);
  return normalizeApiUrl(pageDefaultApi() || FALLBACK_DEFAULT_API, FALLBACK_DEFAULT_API);
}

function initialApiConfig() {
  const stored = storageGet(LS_KEY, '');
  const { urlStr, pubkeyB64 } = parseApiConfig(stored);
  const url = (urlStr && isSafeApiTransport(urlStr)) ? normalizeApiUrl(urlStr, DEFAULT_API) : hostedDefaultApi();
  const trusted = getTrustedPubkey(url);
  const pubkey = trusted !== null
    ? normalizePubkeyB64(trusted)
    : (normalizePubkeyB64(pubkeyB64) || (url === DEFAULT_API ? normalizePubkeyB64(DEFAULT_API_PUBKEY) : null));
  return { url, pubkeyB64: pubkey };
}

function pageDefaultApi(url = location.href) {
  const pageUrl = url instanceof URL ? url : new URL(url, location.href);
  if (!/^https?:$/.test(pageUrl.protocol)) return '';
  return normalizeApiUrl(pageUrl.origin, FALLBACK_DEFAULT_API);
}

function hostedDefaultApi(url = location.href) {
  const configured = RUNTIME_CONFIG.defaultApiUrl;
  if (configured && isSafeApiTransport(configured)) return normalizeApiUrl(configured, FALLBACK_DEFAULT_API);
  return normalizeApiUrl(pageDefaultApi(url) || FALLBACK_DEFAULT_API, FALLBACK_DEFAULT_API);
}

function setApiQueryParam(url, api, pubkeyB64 = null) {
  const pageApi = pageDefaultApi(url);
  const normalizedApi = isSafeApiTransport(api) ? normalizeApiUrl(api, pageApi || DEFAULT_API) : (pageApi || DEFAULT_API);
  const normalizedPubkey = normalizePubkeyB64(pubkeyB64);
  url.searchParams.delete('api');
  url.searchParams.delete('pin');
  if (!pageApi || normalizedApi !== pageApi) {
    url.searchParams.set('api', apiConfigString(normalizedApi, normalizedPubkey));
  }
}

function setPinQueryParam(url, pubkeyB64) {
  const normalizedPubkey = normalizePubkeyB64(pubkeyB64);
  url.searchParams.delete('pin');
  if (normalizedPubkey) url.searchParams.set('pin', normalizedPubkey);
}

function apiBase(url = apiUrl) {
  return normalizeApiUrl(url, hostedDefaultApi());
}

function apiEndpoint(path, base = apiUrl) {
  return new URL(path, apiBase(base)).toString();
}

function apiHostLabel(url = apiUrl) {
  const base = apiBase(url);
  return base === hostedDefaultApi() ? DEFAULT_API_LABEL + ' (' + base.replace(/^https?:\/\//, '') + ')' : base.replace(/^https?:\/\//, '');
}

function clearPowCache() {
  powContextVersion++;
  clearTimeout(viewRefreshTimer);
  powCache.create = null;
  powCache.view = null;
  powInitPromises.create = null;
  powInitPromises.view = null;
  presolvedViewNonce = null;
  presolveViewPromise = null;
  presolveViewState = null;
  viewRefreshTimer = null;
}

// A different server may have different limits; forget the old ones until /init answers.
function resetServerLimits() {
  maxPlaintextBytes = DEFAULT_MAX_PLAINTEXT_BYTES;
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES;
  maxFileBytes = 0;
  updateComposerLimits();
}

function isPowFresh(entry) {
  return !!entry && entry.expiresAt * 1000 > Date.now() + POW_REFRESH_SKEW_MS;
}

function isGateVisible() {
  return !!gate && !gate.done;
}

function selectedTtl() {
  return +document.querySelector('input[name="ttl"]:checked').value;
}

function plaintextByteLength(text) {
  return te.encode(text).length;
}

function scheduleViewPowRefresh(expiresAt) {
  clearTimeout(viewRefreshTimer);
  if (!expiresAt) return;
  const delay = Math.max(1000, expiresAt * 1000 - Date.now() - POW_REFRESH_SKEW_MS);
  viewRefreshTimer = setTimeout(() => {
    viewRefreshTimer = null;
    if (!isGateVisible()) return;
    powCache.view = null;
    presolvedViewNonce = null;
    presolveViewPromise = null;
    presolveViewState = null;
    startPresolveView();
  }, delay);
}

/* ── Health signal (top-right) ── */
function setHealth(state) {
  healthState = state;
  renderHealth();
}

function renderHealth() {
  const dot = $('apiDot');
  if (!dot) return;
  dot.classList.remove('ok', 'err', 'warn');
  if (healthState !== 'checking') dot.classList.add(healthState);
  const key = { checking: 'HEALTH_CHECKING', ok: 'HEALTH_OK', err: 'HEALTH_ERR', warn: 'HEALTH_NOKEY' }[healthState] || 'HEALTH_CHECKING';
  setText($('healthLbl'), key);
  const title = t('HEALTH_TITLE', { host: apiHostLabel(), state: t(key) });
  $('healthBtn').setAttribute('title', title);
  $('healthBtn').setAttribute('aria-label', title);
  renderServerCard(key);
}

function shortKey(key) {
  return key.length > 14 ? key.slice(0, 6) + '…' + key.slice(-4) : key;
}

// Settings → server: one card with the current server, its state and signing key.
function renderServerCard(stateKey) {
  const card = $('serverCard');
  if (!card) return;
  const base = apiBase();
  const external = isExternalApi(base);
  const dot = $('serverDot');
  dot.classList.remove('ok', 'err', 'warn');
  if (healthState !== 'checking') dot.classList.add(healthState);
  $('serverHost').textContent = base.replace(/^https?:\/\//, '');
  $('serverHost').title = base;
  const badge = $('serverBadge');
  setText(badge, external ? 'SERVER_EXTERNAL' : 'SERVER_THIS_SITE');
  badge.classList.toggle('external', external);
  const meta = $('serverMeta');
  meta.replaceChildren();
  meta.appendChild(i18nEl('span', '', stateKey));
  if (healthState === 'ok' && Number.isFinite(apiLatencyMs)) meta.appendChild(i18nEl('span', '', 'SERVER_LATENCY', { ms: apiLatencyMs }));
  if (apiPubKeyB64) {
    const keyEl = i18nEl('span', 'mono', 'SERVER_KEY', { key: shortKey(apiPubKeyB64) });
    keyEl.title = apiPubKeyB64;
    meta.appendChild(keyEl);
  }
  $('defaultBtn').hidden = base === apiBase(DEFAULT_API);
}

function setServerFormOpen(open) {
  $('serverForm').hidden = !open;
  $('changeServerBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) {
    $('apiInp').value = apiUrl;
    setTimeout(() => { $('apiInp').focus(); $('apiInp').select?.(); }, 40);
  } else {
    setReach('idle', '');
  }
}

function setReach(state, label) {
  const wrap = $('apiReach');
  const dot = $('reachDot');
  wrap.classList.toggle('hidden', !label);
  wrap.classList.toggle('err', state === 'err');
  dot.classList.remove('ok', 'err');
  if (state !== 'idle') dot.classList.add(state);
  $('reachLbl').textContent = label || '';
}

/* ══════════════════════════════════════════════════════
   Signed API transport
   ══════════════════════════════════════════════════════ */
async function readLimitedBytes(response, maxBytes = DEFAULT_RESPONSE_BYTES) {
  const cl = response.headers.get('content-length');
  if (cl && Number.parseInt(cl, 10) > maxBytes) throw new Error('response too large');

  if (!response.body || typeof response.body.getReader !== 'function') {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maxBytes) throw new Error('response too large');
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new Error('response too large');
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  chunks.forEach(chunk => {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  });
  return bytes;
}

async function fetchJson(url, options = {}, timeoutMs = 7000) {
  const { allowUnsigned = false, verifyPubkeyB64, signal, maxResponseBytes = DEFAULT_RESPONSE_BYTES, ...fetchOptions } = options;
  const explicitVerificationKey = Object.prototype.hasOwnProperty.call(options, 'verifyPubkeyB64');
  const rawVerificationKey = explicitVerificationKey ? verifyPubkeyB64 : apiPubKeyB64;
  const verificationKey = rawVerificationKey ? normalizePubkeyB64(rawVerificationKey) : null;
  if (rawVerificationKey && !verificationKey) throw new Error('invalid server signing key');

  const controller = new AbortController();
  const abort = () => controller.abort();
  if (signal?.aborted) abort();
  else signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const requestUrl = new URL(url);
    const method = (fetchOptions.method || 'GET').toUpperCase();
    const requestId = b64u(crypto.getRandomValues(new Uint8Array(16)));
    if (fetchOptions.body !== undefined && typeof fetchOptions.body !== 'string') {
      throw new Error('API request body must be a string');
    }
    const requestHash = b64u(await sha256(te.encode(fetchOptions.body || '')));
    const headers = new Headers(fetchOptions.headers);
    headers.set('x-secnote-request-id', requestId);
    let response;
    try {
      response = await fetch(url, {
        ...fetchOptions,
        method,
        headers,
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
        signal: controller.signal,
      });
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
      throw Object.assign(new Error('network error'), { network: true });
    }
    const bytes = await readLimitedBytes(response, maxResponseBytes);

    if (verificationKey) {
      await verifyResponseSignature(response, bytes, verificationKey, {
        method, target: requestUrl.pathname + requestUrl.search, requestId, requestHash,
      });
    } else if (!allowUnsigned) {
      throw Object.assign(new Error('server signing key not configured'), { code: 'no_pubkey' });
    }

    const text = td.decode(bytes);
    let body = null;

    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
    }

    return { response, body };
  } catch (err) {
    if (err && err.name === 'AbortError') throw Object.assign(new Error('request timed out'), { network: true });
    throw err;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

function responseError(response, body, fallback) {
  const message =
    body?.error?.message ||
    body?.message ||
    fallback ||
    ('server error ' + response.status);
  const err = new Error(message);
  err.status = response.status;
  err.code = body?.error?.code || '';
  const retryAfter = Number.parseInt(response?.headers?.get?.('retry-after') || '', 10);
  if (Number.isFinite(retryAfter) && retryAfter > 0) err.retryAfter = retryAfter;
  return err;
}

function appError(key, vars, message) {
  return Object.assign(new Error(message || formatString(BUILTIN_I18N.en[key] || key, vars || null, false)), { i18nKey: key, i18nVars: vars || null });
}

function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return (value >= 10 ? Math.round(value) : Math.round(value * 10) / 10) + ' ' + units[i];
}

function formatUptime(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return days + 'd ' + hours + 'h';
  if (hours > 0) return hours + 'h ' + minutes + 'm';
  return minutes + 'm';
}

// The signed instance passport (docs/ram-only.md) is self-reported by the server process:
// labels, not translations, so they read the same in every language.
function formatRamOnly(ramOnly) {
  if (!ramOnly || typeof ramOnly !== 'object') return '—';
  const flag = (value, yes, no) => (value === true ? yes : value === false ? no : '?');
  return [
    'dumpable:' + flag(ramOnly.dumpable, 'yes', 'no'),
    'coredump:' + flag(ramOnly.core_dump_limit_zero, 'off', 'on'),
    'mlock:' + flag(ramOnly.memory_locked, 'yes', 'no'),
    'swap:' + flag(ramOnly.swap_present, 'yes', 'no'),
    'zeroize:' + flag(ramOnly.zeroize_on_drop, 'yes', 'no'),
  ].join(' · ');
}

function updateServerInfo(body) {
  if (!body || typeof body !== 'object') return;
  const notesEl = $('infoNotes');
  const ramEl = $('infoRam');
  const keyEl = $('infoPubKey');
  const filesEl = $('infoFiles');
  const uptimeEl = $('infoUptime');
  const ramOnlyEl = $('infoRamOnly');
  const binaryEl = $('infoBinary');
  if (notesEl && typeof body.notes === 'number') notesEl.textContent = body.notes.toLocaleString();
  if (ramEl && typeof body.ram_usage === 'string') ramEl.textContent = body.ram_usage.slice(0, 32);
  if (keyEl) keyEl.textContent = typeof body.pubkey === 'string' ? body.pubkey.slice(0, 64) : '—';
  if (filesEl && Number.isInteger(body.max_file_bytes)) {
    if (body.max_file_bytes > 0) setText(filesEl, 'FILES_UP_TO', { limit: formatBytes(body.max_file_bytes) });
    else setText(filesEl, 'FILES_OFF');
  }
  const passport = body.passport && typeof body.passport === 'object' ? body.passport : null;
  if (uptimeEl) uptimeEl.textContent = passport ? formatUptime(passport.uptime_secs) : '—';
  if (ramOnlyEl) {
    ramOnlyEl.textContent = passport ? formatRamOnly(passport.ram_only) : '—';
    if (passport && passport.ram_only && typeof passport.ram_only.memory_lock_detail === 'string') {
      ramOnlyEl.title = passport.ram_only.memory_lock_detail.slice(0, 200);
    } else {
      ramOnlyEl.removeAttribute('title');
    }
  }
  if (binaryEl) {
    const digest = passport && typeof passport.binary_sha256 === 'string' && /^[0-9a-f]{64}$/.test(passport.binary_sha256)
      ? passport.binary_sha256 : null;
    const version = passport && typeof passport.version === 'string' ? passport.version.slice(0, 32) : '';
    binaryEl.textContent = digest ? 'sha256:' + digest + (version ? ' · v' + version : '') : '—';
  }
}

async function pingApi(url) {
  const seq = ++apiCheckSeq;
  const base = apiBase(url);
  if (!apiReachable) setHealth('checking');

  try {
    const startedAt = Date.now();
    const { response, body } = await fetchJson(apiEndpoint('/info', base), {
      headers: { Accept: 'application/json' },
      allowUnsigned: true,
    }, 5000);
    const latency = Date.now() - startedAt;

    if (!response.ok) throw new Error('server error ' + response.status);
    if (seq !== apiCheckSeq || base !== apiBase()) return false;
    updateServerInfo(body);
    if (!apiPubKeyB64 && normalizePubkeyB64(body?.pubkey)) {
      const pageApi = pageDefaultApi();
      if (pageApi && base === pageApi) {
        setApiPubKey(body.pubkey);
        saveTrustedApi(base, body.pubkey);
      }
    } else if (apiPubKeyB64 && base === pageDefaultApi()) {
      saveTrustedApi(base, apiPubKeyB64);
    }
    apiReachable = true;
    apiLatencyMs = latency;
    setHealth(apiPubKeyB64 ? 'ok' : 'warn');
    return true;
  } catch {
    if (seq !== apiCheckSeq || base !== apiBase()) return false;
    apiReachable = false;
    setHealth('err');
    return false;
  }
}

/* ══════════════════════════════════════════════════════
   Proof-of-work challenges & server limits
   ══════════════════════════════════════════════════════ */
// Accepts only the Argon2id scheme and bounds its parameters, so a misconfigured or hostile
// API can never make this device allocate unbounded memory or grind for hours.
function validatePowScheme(pow) {
  if (pow?.alg !== POW_ALG) throw new Error('unsupported PoW algorithm');
  const { bits, rounds } = pow;
  if (!Number.isInteger(bits) || bits < 1 || bits > MAX_POW_BITS) throw new Error('invalid PoW difficulty');
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > MAX_POW_ROUNDS) throw new Error('invalid PoW rounds');
  const params = pow.params && typeof pow.params === 'object' ? pow.params : {};
  const { m_kib: mKib, t: tCost, p: lanes, tag_bytes: tagBytes, nonce_bytes: nonceBytes } = params;
  if (!Number.isInteger(lanes) || lanes < 1 || lanes > MAX_POW_ARGON2_P) throw new Error('invalid PoW parallelism parameter');
  if (!Number.isInteger(mKib) || mKib < 8 * lanes || mKib > MAX_POW_ARGON2_M_KIB) throw new Error('invalid PoW memory parameter');
  if (!Number.isInteger(tCost) || tCost < 1 || tCost > MAX_POW_ARGON2_T) throw new Error('invalid PoW time parameter');
  if (tagBytes !== 32 || nonceBytes !== POW_NONCE_BYTES) throw new Error('unsupported PoW parameters');
  return { alg: POW_ALG, bits, rounds, params: { m_kib: mKib, t: tCost, p: lanes, tag_bytes: tagBytes, nonce_bytes: nonceBytes } };
}

function applyServerLimits(limits) {
  if (!limits || typeof limits !== 'object') throw new Error('missing server limits');
  const textLimit = limits.max_plaintext_bytes;
  const blobLimit = limits.max_blob_bytes;
  const fileLimit = limits.max_file_bytes === undefined ? 0 : limits.max_file_bytes;
  if (!Number.isInteger(textLimit) || textLimit < 1 || textLimit > 1024 * 1024) throw new Error('invalid plaintext limit');
  if (!Number.isInteger(blobLimit) || blobLimit < b64urlEncodedLen(AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES) ||
      blobLimit > ABSOLUTE_MAX_BLOB_BYTES) {
    throw new Error('invalid encrypted blob limit');
  }
  if (!Number.isInteger(fileLimit) || fileLimit < 0 || fileLimit > MAX_FILE_BYTES_CAP) throw new Error('invalid file limit');
  const blobPlaintext = Math.floor(blobLimit * 3 / 4) - AES_GCM_IV_BYTES - AES_GCM_TAG_BYTES;
  maxPlaintextBytes = Math.max(1, Math.min(textLimit, DEFAULT_MAX_PLAINTEXT_BYTES, blobPlaintext));
  maxBlobBytes = blobLimit;
  maxFileBytes = fileLimit > 0
    ? Math.max(0, Math.min(fileLimit, blobPlaintext - FILE_ENVELOPE_OVERHEAD_BYTES - maxPlaintextBytes))
    : 0;
  updateComposerLimits();
}

async function getPowInit(scope) {
  const cached = powCache[scope];
  if (isPowFresh(cached)) return cached;

  const pending = powInitPromises[scope];
  if (pending) return await pending.promise;

  const base = apiBase();
  const version = powContextVersion;
  const request = (async () => {
    const { response, body } = await fetchJson(
      apiEndpoint('/api/v1/init?scope=' + encodeURIComponent(scope), base),
      { headers: { Accept: 'application/json' } },
      7000
    );

    if (!response.ok || !body?.ok || !body?.pow?.challenge) {
      throw responseError(response, body, 'failed to initialize request');
    }
    if (powContextVersion !== version || apiBase() !== base) {
      throw new Error('PoW initialization was invalidated');
    }

    const { alg, bits, rounds, params } = validatePowScheme(body.pow);
    const challenge = body.pow.challenge;
    if (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge)) {
      throw new Error('invalid challenge format');
    }
    const expiresAt = body.pow.expires_at;
    const nowSec = Date.now() / 1000;
    if (!Number.isInteger(expiresAt) || expiresAt <= nowSec || expiresAt > nowSec + 86400) {
      throw new Error('invalid expires_at');
    }
    applyServerLimits(body.limits);
    const entry = { challenge, alg, bits, rounds, params, expiresAt };
    if (powContextVersion !== version || apiBase() !== base) {
      throw new Error('PoW initialization was invalidated');
    }
    powCache[scope] = entry;
    if (scope === 'create') lastCreatePow = entry;
    return entry;
  })();

  const handle = { promise: request };
  powInitPromises[scope] = handle;
  try {
    return await request;
  } finally {
    if (powInitPromises[scope] === handle) powInitPromises[scope] = null;
  }
}

/* ══════════════════════════════════════════════════════
   Encoding / crypto
   ══════════════════════════════════════════════════════ */
function b64u(bytes) {
  const chunkSize = 0x8000;
  let raw = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    raw += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64std(bytes) {
  const chunkSize = 0x8000;
  let raw = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    raw += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(raw);
}

function b64urlEncodedLen(rawBytes) {
  return Math.floor((rawBytes * 4 + 2) / 3);
}

function fromb64u(s, expectedBytes = null, label = 'base64url value') {
  if (typeof s !== 'string' || !B64U_RE.test(s) || s.length % 4 === 1) {
    throw new Error('invalid ' + label);
  }
  if (expectedBytes !== null && s.length !== b64urlEncodedLen(expectedBytes)) {
    throw new Error('invalid ' + label + ' length');
  }
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (expectedBytes !== null && out.length !== expectedBytes) {
    throw new Error('invalid ' + label + ' length');
  }
  if (b64u(out) !== s) throw new Error('non-canonical ' + label);
  return out;
}

function concatBytes(...parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function leadingZeroBits(bytes, bits) {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;

  for (let i = 0; i < full; i++) {
    if (bytes[i] !== 0) return false;
  }
  if (rem === 0) return true;

  const mask = 0xFF << (8 - rem);
  return (bytes[full] & mask) === 0;
}

// SHA-256(ttl_be64 ‖ blob). The blob is ASCII base64url, so it is encoded straight into the
// buffer without an extra copy (it can be tens of megabytes when files are attached).
async function payloadHashCreate(ttl, blob) {
  const bytes = new Uint8Array(8 + blob.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Math.floor(ttl / 0x100000000), false);
  view.setUint32(4, ttl >>> 0, false);
  const { written } = te.encodeInto(blob, bytes.subarray(8));
  if (written !== blob.length) throw new Error('blob must be base64url');
  return sha256(bytes);
}

async function payloadHashView(nid) {
  return sha256(te.encode('view:' + nid));
}

function nonceFromCounter(counter) {
  const nonce = new Uint8Array(POW_NONCE_BYTES);
  const view = new DataView(nonce.buffer);
  view.setUint32(0, counter >>> 0, true);
  view.setUint32(4, Math.floor(counter / 0x100000000), true);
  return nonce;
}

/* ── Note envelope: text-only notes stay raw UTF-8; notes with files use "\0SNF" v1 ── */
function cleanFileName(name) {
  const cleaned = String(name || '')
    // Control characters, path separators and characters Windows refuses in file names.
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_')
    // Bidirectional overrides can disguise "invoice‮fdp.exe" as "invoiceexe.pdf".
    .replace(/[؜‎‏‪-‮⁦-⁩]/g, '')
    .replace(/^[.\s]+/, '')
    .trim()
    .slice(0, 180);
  return cleaned || 'file';
}

function cleanMime(type) {
  const value = String(type || '').toLowerCase();
  return /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/.test(value) ? value : 'application/octet-stream';
}

function hasEnvelopeMagic(bytes) {
  if (bytes.length < FILE_ENVELOPE_PREFIX_BYTES) return false;
  for (let i = 0; i < FILE_ENVELOPE_MAGIC.length; i++) if (bytes[i] !== FILE_ENVELOPE_MAGIC[i]) return false;
  return true;
}

async function readFileBytes(file) {
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.length !== file.size) throw new Error('size changed');
    return bytes;
  } catch {
    throw appError('ERR_FILE_READ', { name: cleanFileName(file.name) });
  }
}

async function buildPlaintext(text, files) {
  const textBytes = te.encode(text);
  if (textBytes.byteLength > maxPlaintextBytes) {
    throw appError('ERR_TEXT_TOO_LARGE', { size: formatBytes(textBytes.byteLength), limit: formatBytes(maxPlaintextBytes) },
      'note exceeds ' + maxPlaintextBytes.toLocaleString() + ' bytes');
  }
  if (!files.length) return textBytes;
  if (maxFileBytes <= 0) throw appError('ERR_FILES_DISABLED');
  if (files.length > MAX_FILES) throw appError('ERR_FILES_TOO_MANY', { count: MAX_FILES });
  const total = files.reduce((sum, file) => sum + file.size, 0);
  if (total > maxFileBytes) throw appError('ERR_FILES_TOO_LARGE', { size: formatBytes(total), limit: formatBytes(maxFileBytes) });
  const header = te.encode(JSON.stringify({
    v: 1,
    text: textBytes.byteLength,
    files: files.map(file => ({ name: cleanFileName(file.name), type: cleanMime(file.type), size: file.size })),
  }));
  if (FILE_ENVELOPE_PREFIX_BYTES + header.length > FILE_ENVELOPE_OVERHEAD_BYTES) throw appError('ERR_FILES_TOO_MANY', { count: MAX_FILES });
  const out = new Uint8Array(FILE_ENVELOPE_PREFIX_BYTES + header.length + textBytes.length + total);
  out.set(FILE_ENVELOPE_MAGIC, 0);
  new DataView(out.buffer).setUint32(FILE_ENVELOPE_MAGIC.length, header.length, false);
  let offset = FILE_ENVELOPE_PREFIX_BYTES;
  out.set(header, offset); offset += header.length;
  out.set(textBytes, offset); offset += textBytes.length;
  for (const file of files) {
    const bytes = await readFileBytes(file);
    out.set(bytes, offset);
    offset += bytes.length;
    bytes.fill(0);
  }
  return out;
}

function decodeNotePlaintext(bytes) {
  if (!hasEnvelopeMagic(bytes)) return { text: td.decode(bytes), files: [] };
  const malformed = () => appError('ERR_MALFORMED', null, 'malformed note envelope');
  const headerLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(FILE_ENVELOPE_MAGIC.length, false);
  if (headerLen > FILE_ENVELOPE_OVERHEAD_BYTES - FILE_ENVELOPE_PREFIX_BYTES || FILE_ENVELOPE_PREFIX_BYTES + headerLen > bytes.length) throw malformed();
  let header;
  try {
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(FILE_ENVELOPE_PREFIX_BYTES, FILE_ENVELOPE_PREFIX_BYTES + headerLen)));
  } catch { throw malformed(); }
  if (!header || header.v !== 1 || !Number.isInteger(header.text) || header.text < 0 ||
      !Array.isArray(header.files) || header.files.length > MAX_FILES) throw malformed();
  let offset = FILE_ENVELOPE_PREFIX_BYTES + headerLen;
  if (offset + header.text > bytes.length) throw malformed();
  const text = td.decode(bytes.subarray(offset, offset + header.text));
  offset += header.text;
  const files = header.files.map(meta => {
    if (!meta || typeof meta.name !== 'string' || typeof meta.type !== 'string' ||
        !Number.isInteger(meta.size) || meta.size < 0 || offset + meta.size > bytes.length) throw malformed();
    const data = bytes.subarray(offset, offset + meta.size);
    offset += meta.size;
    return { name: cleanFileName(meta.name), type: cleanMime(meta.type), size: meta.size, data };
  });
  if (offset !== bytes.length) throw malformed();
  return { text, files };
}

async function encrypt(text, files = []) {
  const plaintext = await buildPlaintext(text, files);
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  );
  plaintext.fill(0);
  const blobBytes = concatBytes(iv, ciphertext);
  const viewToken = await sha256(keyBytes);

  return {
    blob: b64u(blobBytes),
    keyB64: b64u(keyBytes),
    viewTokenB64: b64u(viewToken),
  };
}

// Returns { text, files: [{ name, type, size, data }] }.
async function decrypt(blobB64, keyB64) {
  if (typeof blobB64 !== 'string' || blobB64.length > Math.max(maxBlobBytes, DEFAULT_MAX_BLOB_BYTES)) throw new Error('blob too large');
  if (typeof keyB64 !== 'string' || !KEY_RE.test(keyB64)) throw new Error('invalid key format');
  const blobBytes = fromb64u(blobB64, null, 'blob');
  if (blobBytes.length < AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES) throw new Error('invalid blob length');
  const iv = blobBytes.slice(0, AES_GCM_IV_BYTES);
  const ciphertext = blobBytes.subarray(AES_GCM_IV_BYTES);
  const keyBytes = fromb64u(keyB64, AES_KEY_BYTES, 'key');
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext));
  return decodeNotePlaintext(plaintext);
}

async function viewTokenFromKey(keyB64) {
  return b64u(await sha256(fromb64u(keyB64, AES_KEY_BYTES, 'key')));
}

function setApiPubKey(b64) {
  const nextKey = normalizePubkeyB64(b64);
  if (nextKey !== apiPubKeyB64) clearPowCache();
  apiPubKeyB64 = nextKey;
  apiVerifyKey = null;
}

async function importEd25519VerifyKey(b64) {
  const keyBytes = fromb64u(b64, 32, 'Ed25519 public key');
  return await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'Ed25519' }, false, ['verify']
  );
}

async function verifyResponseSignature(response, bytes, pubkeyB64, context) {
  const sigB64 = response.headers.get('x-secnote-sig-v2');
  if (!sigB64) throw new Error('response signature missing');
  const sigBytes = fromb64u(sigB64, 64, 'response signature');
  const verifyKey = apiVerifyKey?.pubkey === pubkeyB64
    ? apiVerifyKey.key : await importEd25519VerifyKey(pubkeyB64);
  if (pubkeyB64 === apiPubKeyB64) apiVerifyKey = { pubkey: pubkeyB64, key: verifyKey };
  const prefix = te.encode('secnote-response-v2\n' + context.method + '\n' + context.target + '\n' +
    context.requestId + '\n' + context.requestHash + '\n' + response.status + '\n');
  const valid = await crypto.subtle.verify({ name: 'Ed25519' }, verifyKey, sigBytes, concatBytes(prefix, bytes));
  if (!valid) throw new Error('response signature invalid');
}

/* ── Proof-of-work solving ── */
function solvePoWWithWorker(payload, onProgress) {
  return new Promise((resolve, reject) => {
    let worker;
    let timer = null;
    const finish = (fn, value) => {
      if (timer) clearTimeout(timer);
      if (worker) worker.terminate();
      fn(value);
    };

    try {
      worker = new Worker(new URL('./pow-worker.js', location.href));
    } catch (err) {
      reject(err);
      return;
    }

    if (payload.expiresAt) {
      const timeoutMs = Math.max(1, payload.expiresAt * 1000 - Date.now());
      timer = setTimeout(() => finish(reject, Object.assign(new Error('PoW challenge expired'), { expired: true })), timeoutMs);
    }

    worker.addEventListener('message', event => {
      const data = event.data || {};
      if (data.ok && data.nonce) {
        finish(resolve, data.nonce);
        return;
      }
      if (data.fatal) {
        finish(reject, new Error(data.message || 'PoW worker failed'));
        return;
      }
      if (Number.isInteger(data.found) && Number.isInteger(data.rounds)) onProgress?.(data.found, data.rounds);
    });

    worker.addEventListener('error', event => {
      finish(reject, new Error(event.message || 'PoW worker failed'));
    });

    worker.postMessage({
      challenge: payload.challenge,
      payloadHash: b64u(payload.payloadHash),
      bits: payload.bits,
      rounds: payload.rounds,
      params: payload.params,
    });
  });
}

// Fallback for file:// pages and browsers without Web Workers. Yields to the event loop
// between evaluations so the page stays responsive.
async function solvePoWInMainThread(payload, onProgress) {
  if (typeof SecNoteArgon2 === 'undefined') throw new Error('argon2.js is not loaded');
  const challengeBytes = fromb64u(payload.challenge, 24, 'challenge');
  const salt = await sha256(concatBytes(te.encode(POW_ARGON2_SALT_DOMAIN), challengeBytes, payload.payloadHash));
  const { m_kib: m, t: tCost, p } = payload.params;
  const opts = { m, t: tCost, p, tagLength: 32, maxMemoryKib: m };
  const solutions = [];
  let counter = 0;
  try {
    while (solutions.length < payload.rounds) {
      const nonce = nonceFromCounter(counter++);
      if (leadingZeroBits(SecNoteArgon2.argon2id(nonce, salt, opts), payload.bits)) {
        solutions.push(nonce);
        onProgress?.(solutions.length, payload.rounds);
      }
      if (payload.expiresAt && Date.now() >= payload.expiresAt * 1000) {
        throw Object.assign(new Error('PoW challenge expired'), { expired: true });
      }
      if (counter % 4 === 0) await new Promise(resolve => setTimeout(resolve, 0));
    }
  } finally {
    SecNoteArgon2.releaseMemory();
  }
  return b64u(concatBytes(...solutions));
}

async function solvePoW(payload, onProgress) {
  if (location.protocol === 'file:') return solvePoWInMainThread(payload, onProgress);

  try {
    return await solvePoWWithWorker(payload, onProgress);
  } catch (err) {
    if (err?.expired) throw err;
    return solvePoWInMainThread(payload, onProgress);
  }
}

/* ── Share links ── */
function buildHostedShareUrl(nid, keyB64) {
  const remoteBase = apiBase();
  if (/^https:\/\//.test(remoteBase) && !isLoopbackHostname(new URL(remoteBase).hostname)) {
    const url = new URL(remoteBase);
    url.pathname = '/';
    url.search = '';
    url.searchParams.set('p', nid);
    setPinQueryParam(url, apiPubKeyB64);
    url.hash = keyB64;
    return url.toString();
  }

  if (!/^https?:$/.test(location.protocol)) {
    return buildLocalShareUrl(nid, keyB64);
  }

  const url = new URL(location.origin);
  url.pathname = '/';
  url.search = '';
  url.searchParams.set('p', nid);
  setApiQueryParam(url, apiUrl, apiPubKeyB64);
  if (apiBase(url) === remoteBase) setPinQueryParam(url, apiPubKeyB64);
  url.hash = keyB64;
  return url.toString();
}

function buildLocalShareUrl(nid, keyB64) {
  const url = new URL(location.href);
  url.search = '';
  url.searchParams.set('p', nid);
  setApiQueryParam(url, apiUrl, apiPubKeyB64);
  url.hash = keyB64;
  return url.toString();
}

function buildComposeUrl() {
  const url = new URL(location.href);
  url.search = '';
  setApiQueryParam(url, apiUrl);
  url.hash = '';
  return url.toString();
}

function parseSharedLink(raw) {
  let parsed;

  try {
    parsed = new URL(raw.trim(), location.href);
  } catch {
    throw new Error('paste a valid shared link');
  }

  const nid = parsed.searchParams.get('p');
  const key = parsed.hash.replace(/^#/, '');
  if (!nid || !key) throw new Error('link must include both note id and #key');
  if (!NID_RE.test(nid)) throw new Error('invalid note id format');
  if (!KEY_RE.test(key)) throw new Error('invalid key format');

  const rawApiParam = parsed.searchParams.get('api') ||
    (/^https?:$/.test(parsed.protocol) ? parsed.origin : apiUrl);
  const rawPinParam = parsed.searchParams.get('pin');
  const { urlStr: rawApiUrl, pubkeyB64: linkPubkey } = parseApiConfig(rawApiParam);
  if (!isSafeApiTransport(rawApiUrl)) throw new Error('link API must be HTTPS, or HTTP on localhost');
  if (linkPubkey && !normalizePubkeyB64(linkPubkey)) throw new Error('invalid API public key');
  if (rawPinParam && !normalizePubkeyB64(rawPinParam)) throw new Error('invalid API pin');
  if (linkPubkey && rawPinParam && linkPubkey !== rawPinParam) throw new Error('conflicting API pins');
  const derivedApi = normalizeApiUrl(rawApiUrl);

  return {
    nid,
    key,
    api: derivedApi,
    pubkeyB64: normalizePubkeyB64(linkPubkey) || normalizePubkeyB64(rawPinParam),
  };
}

async function openSharedLink(raw) {
  const link = parseSharedLink(raw);
  const url = new URL(location.href);
  url.search = '';
  url.searchParams.set('p', link.nid);
  const fallbackApi = hostedDefaultApi(url);
  if (link.api && (link.api !== fallbackApi || link.pubkeyB64)) {
    if (link.api === fallbackApi && link.pubkeyB64) {
      url.searchParams.set('pin', link.pubkeyB64);
    } else {
      url.searchParams.set('api', apiConfigString(link.api, link.pubkeyB64));
    }
  }
  url.hash = link.key;

  history.pushState(null, '', url.toString());
  await route();
}

/* ══════════════════════════════════════════════════════
   Chat rendering
   ══════════════════════════════════════════════════════ */
function h(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = text;
  return el;
}

function iconEl(name, className) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('aria-hidden', 'true');
  if (className) svg.setAttribute('class', className);
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.appendChild(use);
  return svg;
}

function i18nEl(tag, className, key, vars) {
  return setText(h(tag, className), key, vars);
}

function i18nHtmlEl(tag, className, key, vars) {
  return setHtml(h(tag, className), key, vars);
}

function actionButton(className, key, onClick, iconName) {
  const btn = h('button', className);
  btn.type = 'button';
  if (iconName) btn.appendChild(iconEl(iconName));
  btn.appendChild(i18nEl('span', '', key));
  btn.addEventListener('click', onClick);
  return btn;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// The greeting steps aside as soon as the composer is in use, and for good once the chat has messages.
function composerInUse() {
  const input = $('noteInput');
  return document.activeElement === input || !!input.value || attachments.length > 0;
}

function updateHero() {
  const hero = $('hero');
  hero.classList.toggle('hidden', messageCount > 0);
  hero.classList.toggle('away', messageCount === 0 && composerInUse());
}

function scrollChatToEnd() {
  const chat = $('chat');
  requestAnimationFrame(() => { chat.scrollTop = chat.scrollHeight; });
}

function addMessage(role, variant) {
  const root = h('div', 'msg msg-' + role + (variant ? ' msg-' + variant : ''));
  if (role === 'bot') {
    const avatar = h('div', 'avatar');
    avatar.appendChild(iconEl('lock'));
    root.appendChild(avatar);
  }
  const col = h('div', 'msg-col');
  const bubble = h('div', 'bubble');
  col.appendChild(bubble);
  root.appendChild(col);
  $('chatLog').appendChild(root);
  messageCount++;
  updateHero();
  scrollChatToEnd();
  let removed = false;
  return {
    root, col, bubble,
    remove() {
      if (removed) return;
      removed = true;
      root.remove();
      messageCount = Math.max(0, messageCount - 1);
      updateHero();
    },
  };
}

function addBotNotice(key, vars, variant) {
  const msg = addMessage('bot', variant);
  msg.bubble.appendChild(i18nEl('p', '', key, vars));
  return msg;
}

// "Typing" bubble whose status line changes as the request moves along.
function createTyping(container) {
  const row = h('div', 'typing');
  const dots = h('span', 'dots');
  dots.appendChild(h('i'));
  dots.appendChild(h('i'));
  dots.appendChild(h('i'));
  const check = iconEl('check', 'typing-check');
  const text = h('span', 'typing-txt');
  const progress = h('span', 'typing-progress');
  row.appendChild(dots);
  row.appendChild(check);
  row.appendChild(text);
  row.appendChild(progress);
  container.appendChild(row);
  let shownAt = Date.now();
  return {
    row,
    setStatus(key, { done = false, vars = null } = {}) {
      row.classList.toggle('done', done);
      row.classList.remove('hidden');
      progress.textContent = '';
      setText(text, key, vars);
      text.classList.remove('typing-txt');
      void text.offsetWidth;
      text.classList.add('typing-txt');
      shownAt = Date.now();
    },
    setProgress(found, rounds) {
      progress.textContent = rounds > 1 ? Math.min(found, rounds) + '/' + rounds : '';
    },
    async hold(ms) {
      const left = ms - (Date.now() - shownAt);
      if (left > 0) await delay(left);
    },
    hide() { row.classList.add('hidden'); },
  };
}

function addTyping(statusKey) {
  const msg = addMessage('bot');
  const typing = createTyping(msg.bubble);
  if (statusKey) typing.setStatus(statusKey);
  return Object.assign(msg, { typing });
}

function describeError(err) {
  if (err?.i18nKey) return { key: err.i18nKey, vars: err.i18nVars };
  const code = err?.code || '';
  const retryAfter = Number.isFinite(err?.retryAfter) ? err.retryAfter : null;
  if (code === 'rate_limited') return { key: 'ERR_RATE', vars: { seconds: retryAfter || 60 } };
  if (code === 'banned') return { key: 'ERR_BANNED', vars: { seconds: retryAfter || 300 } };
  if (code === 'server_busy') return { key: 'ERR_BUSY' };
  if (['blob_too_large', 'body_too_large', 'plaintext_too_large'].includes(code) || err?.status === 413) return { key: 'ERR_TOO_LARGE' };
  if (code === 'challenge_expired' || err?.expired) return { key: 'ERR_EXPIRED' };
  if (err?.network) return { key: 'ERR_UNREACHABLE' };
  return { key: 'ERR_GENERIC', vars: { message: String(err?.message || 'error').slice(0, 300) } };
}

function showErrorIn(msg, err, retry) {
  msg.root.classList.add('msg-error');
  msg.bubble.replaceChildren();
  const { key, vars } = describeError(err);
  msg.bubble.appendChild(i18nEl('p', '', key, vars));
  if (retry) {
    const actions = h('div', 'link-actions');
    actions.appendChild(actionButton('btn btn-ghost btn-sm', 'RETRY', retry));
    msg.bubble.appendChild(actions);
  }
}

function fileChip(name, size, onRemove) {
  const chip = h('span', 'file-chip');
  chip.appendChild(iconEl('file'));
  const nameEl = h('span', 'file-name', name);
  nameEl.title = name;
  chip.appendChild(nameEl);
  chip.appendChild(h('span', 'file-size', formatBytes(size)));
  if (onRemove) {
    const remove = h('button', 'icon-btn');
    remove.type = 'button';
    remove.setAttribute('aria-label', t('REMOVE_FILE', { name }));
    remove.appendChild(iconEl('x'));
    remove.addEventListener('click', onRemove);
    chip.appendChild(remove);
  }
  return chip;
}

function addUserMessage(text, files = []) {
  const msg = addMessage('user');
  if (text) {
    const body = h('div', 'bubble-text', text);
    msg.bubble.appendChild(body);
  } else {
    msg.bubble.remove();
  }
  if (files.length) {
    const list = h('div', 'msg-files');
    files.forEach(file => list.appendChild(fileChip(cleanFileName(file.name), file.size)));
    msg.col.appendChild(list);
  }
  // After the link is issued the secret is blurred, so it is not left readable on screen.
  msg.mask = () => {
    if (!text) return;
    msg.root.classList.add('secret-masked');
    const hint = i18nEl('span', 'mask-hint', 'SENT_HIDDEN');
    const toggle = () => msg.root.classList.toggle('secret-masked');
    msg.bubble.addEventListener('click', toggle);
    hint.addEventListener('click', toggle);
    msg.col.appendChild(hint);
  };
  return msg;
}

function copyButton(key, getText, className = 'btn btn-ghost btn-sm') {
  let resetTimer = null;
  const btn = actionButton(className, key, async () => {
    const label = btn.querySelector('span');
    try {
      await navigator.clipboard.writeText(getText());
      setText(label, 'LINK_COPIED');
    } catch {
      setText(label, 'LINK_COPY_FAILED');
    }
    clearTimeout(resetTimer);
    resetTimer = setTimeout(() => setText(label, key), 1800);
  });
  return btn;
}

function ttlLabelKey(ttl) {
  return ttl === 43200 ? 'TTL_SHORT_12' : 'TTL_SHORT_24';
}

// The link carries the key, so it stays blurred: hover shows it on a desktop, a click or tap
// shows it for LINK_REVEAL_MS and then it blurs again. Copy and QR work without revealing it.
function maskLink(el) {
  el.classList.add('masked');
  el.tabIndex = 0;
  el.title = t('SENT_HIDDEN');
  let timer = null;
  el.addEventListener('click', () => {
    el.classList.add('revealed');
    clearTimeout(timer);
    timer = setTimeout(() => el.classList.remove('revealed'), LINK_REVEAL_MS);
  });
  return el;
}

function renderLinkReply(msg, { url, nid }) {
  msg.bubble.replaceChildren();
  msg.bubble.appendChild(i18nEl('p', '', 'LINK_READY'));

  const box = h('div', 'link-box');
  box.setAttribute('aria-label', 'Note link');
  const hashAt = url.indexOf('#');
  const text = h('span', 'link-text');
  text.appendChild(document.createTextNode(hashAt >= 0 ? url.slice(0, hashAt) : url));
  if (hashAt >= 0) text.appendChild(h('span', 'link-key', url.slice(hashAt)));
  box.appendChild(text);
  msg.bubble.appendChild(maskLink(box));

  const actions = h('div', 'link-actions');
  actions.appendChild(copyButton('LINK_COPY', () => url, 'btn btn-accent btn-sm'));
  const qrWrap = h('div', 'qr-wrap hidden');
  const qrBtn = actionButton('btn btn-ghost btn-sm', 'LINK_QR', () => {
    const label = qrBtn.querySelector('span');
    if (!qrWrap.classList.contains('hidden')) {
      qrWrap.classList.add('hidden');
      setText(label, 'LINK_QR');
      return;
    }
    qrWrap.classList.remove('hidden');
    setText(label, 'LINK_QR_HIDE');
    if (!qrWrap.firstChild) {
      try {
        if (typeof QRCode === 'undefined') throw new Error('qrcode.min.js missing');
        qrWrap.appendChild(QRCode({ msg: url, dim: 168, pad: 1, ecl: 'M' }));
      } catch {
        qrWrap.appendChild(i18nEl('span', 'small', 'LINK_QR_FAILED'));
      }
    }
  });
  actions.appendChild(qrBtn);
  msg.bubble.appendChild(actions);
  msg.bubble.appendChild(qrWrap);

  if (location.protocol === 'file:') {
    const local = buildLocalShareUrl(nid, url.slice(hashAt + 1));
    msg.bubble.appendChild(i18nEl('p', 'link-hint', 'LINK_LOCAL_COPY'));
    const localBox = h('div', 'link-box');
    localBox.appendChild(h('span', 'link-text', local));
    msg.bubble.appendChild(maskLink(localBox));
  }
  msg.root.classList.add('msg-link');
  scrollChatToEnd();
}

function revokeUrl(url) {
  try { URL.revokeObjectURL(url); } catch {}
  objectUrls.delete(url);
}

function downloadFile(file, urls) {
  const blob = new Blob([file.data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  objectUrls.add(url);
  urls.add(url);
  const a = h('a');
  a.href = url;
  a.download = file.name;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => { revokeUrl(url); urls.delete(url); }, 60000);
}

function renderReceivedFile(file, urls) {
  const wrap = h('div', 'note-file');
  if (PREVIEW_TYPES.has(file.type) && file.size > 0 && file.size <= MAX_PREVIEW_BYTES) {
    const img = h('img');
    img.alt = file.name;
    img.src = 'data:' + file.type + ';base64,' + b64std(file.data);
    wrap.appendChild(img);
  }
  const chip = fileChip(file.name, file.size);
  chip.appendChild(actionButton('btn btn-ghost btn-sm', 'FILE_DOWNLOAD', () => downloadFile(file, urls), 'download'));
  wrap.appendChild(chip);
  return wrap;
}

function wipeNote(note) {
  note.text = '';
  for (const file of note.files) {
    try { file.data.fill(0); } catch {}
    file.data = new Uint8Array(0);
  }
}

function renderNote(note) {
  const msg = addMessage('bot');
  msg.bubble.appendChild(i18nEl('p', '', 'NOTE_TITLE'));
  const urls = new Set();
  if (note.text) msg.bubble.appendChild(h('div', 'note-text', note.text));
  if (note.files.length) {
    const list = h('div', 'note-files');
    note.files.forEach(file => list.appendChild(renderReceivedFile(file, urls)));
    msg.bubble.appendChild(list);
  }
  const opened = { msg, note, urls };
  const actions = h('div', 'note-actions');
  if (note.text) actions.appendChild(copyButton('NOTE_COPY', () => opened.note.text));
  actions.appendChild(actionButton('btn btn-danger-ol btn-sm', 'NOTE_BURN', () => burnNote(opened), 'flame'));
  msg.bubble.appendChild(actions);
  msg.bubble.appendChild(i18nEl('p', 'note-hint', 'NOTE_DESTROYED'));
  openedNotes.add(opened);
  return opened;
}

function burnNote(opened) {
  wipeNote(opened.note);
  opened.urls.forEach(revokeUrl);
  opened.urls.clear();
  const gone = h('p', 'gone-mark');
  gone.appendChild(iconEl('flame'));
  gone.appendChild(i18nEl('span', '', 'NOTE_BURNED'));
  opened.msg.bubble.replaceChildren(gone);
  openedNotes.delete(opened);
  curKey = '';
}

function renderBurned() {
  const msg = addMessage('bot', 'warn');
  msg.bubble.appendChild(i18nEl('p', '', 'BURNED_TITLE')).classList.add('strong');
  msg.bubble.appendChild(i18nEl('p', 'note-hint', 'BURNED_SUB'));
  return msg;
}

/* ── /faq: animated explainer ── */
// Seven scenes, like a short video. Actor positions per scene (x, y, scale, opacity relative to
// where each actor is drawn in #tplExplainer); CSS transitions move them, CSS keyframes add the
// small effects of each scene, and the progress bar of the current scene drives autoplay.
const EX_DURATIONS = [3600, 4600, 5400, 4600, 4800, 7000, 4800];
const EX_HIDDEN = { o: 0 };
const EX_TRACK = {
  sender: [{}, {}, {}, { o: 0.5 }, {}, { o: 0.5 }, { o: 0.45 }],
  server: [{ o: 0.35 }, { o: 0.35 }, { o: 0.35 }, {}, { o: 0.55 }, {}, {}],
  recipient: [{ o: 0.35 }, { o: 0.35 }, { o: 0.35 }, { o: 0.35 }, { o: 0.55 }, {}, { o: 0.85 }],
  plain: [{}, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN],
  cipher: [EX_HIDDEN, {}, {}, { o: 0.3 }, { o: 0.3 }, { o: 0.3 }, { o: 0.3 }],
  lockbadge: [{ o: 0, s: 0.4 }, {}, {}, { o: 0, s: 0.4 }, { o: 0, s: 0.4 }, { o: 0, s: 0.4 }, { o: 0, s: 0.4 }],
  pow: [EX_HIDDEN, EX_HIDDEN, {}, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN, EX_HIDDEN],
  key: [{ o: 0, s: 0.4 }, {}, {}, {}, { x: -94, y: 194, s: 0.5, o: 0 }, { x: -94, y: 194, s: 0.5, o: 0 }, { x: -94, y: 194, s: 0.5, o: 0 }],
  pkg: [{ o: 0, s: 0.6 }, { o: 0, s: 0.6 }, { o: 0, s: 0.6 }, { x: 212, y: 46 }, { x: 212, y: 46 }, { x: 424 }, { x: 424, o: 0 }],
  link: [{ o: 0, y: 12 }, { o: 0, y: 12 }, { o: 0, y: 12 }, { o: 0, y: 12 }, {}, { x: 424 }, { x: 424, o: 0.45 }],
};

function explainerPowVars() {
  const pow = lastCreatePow || { bits: 4, rounds: 4, params: { m_kib: 4096 } };
  return { mem: formatBytes(pow.params.m_kib * 1024), rounds: pow.rounds, tries: pow.rounds * 2 ** pow.bits };
}

function prefersReducedMotion() {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function renderFaq() {
  explainers.forEach(player => player.pause());
  const msg = addMessage('bot');
  msg.root.classList.add('msg-wide');
  const wrap = h('div', 'ex');
  wrap.appendChild(i18nEl('p', 'ex-head', 'FAQ_TITLE'));

  const frame = h('div', 'ex-frame');
  const tpl = $('tplExplainer');
  const svg = tpl && tpl.content && tpl.content.firstElementChild ? tpl.content.firstElementChild.cloneNode(true) : null;
  if (svg) frame.appendChild(svg);
  wrap.appendChild(frame);

  const caption = h('div', 'ex-caption');
  const step = h('span', 'ex-step mono');
  const title = h('p', 'ex-title');
  const tech = h('p', 'ex-tech');
  caption.appendChild(step);
  caption.appendChild(title);
  caption.appendChild(tech);
  wrap.appendChild(caption);

  const controls = h('div', 'ex-controls');
  const playBtn = h('button', 'icon-btn ex-play');
  playBtn.type = 'button';
  const segs = h('div', 'ex-segs');
  controls.appendChild(playBtn);
  controls.appendChild(segs);
  wrap.appendChild(controls);
  if (maxFileBytes > 0) wrap.appendChild(i18nEl('p', 'note-hint', 'EX_FILES', { limit: formatBytes(maxFileBytes) }));
  wrap.appendChild(i18nHtmlEl('p', 'note-hint', 'FAQ_FOOT'));
  msg.bubble.appendChild(wrap);

  const actors = {};
  if (svg) Object.keys(EX_TRACK).forEach(name => { actors[name] = svg.querySelector('.ex-' + name); });
  const reduced = prefersReducedMotion();
  const player = { scene: 0, paused: reduced, ended: false };

  const fills = EX_DURATIONS.map((ms, index) => {
    const seg = h('button', 'ex-seg');
    seg.type = 'button';
    seg.setAttribute('aria-label', t('EX_STEP', { n: index + 1 }));
    const track = h('i');
    const fill = h('b');
    fill.style.animationDuration = ms + 'ms';
    track.appendChild(fill);
    seg.appendChild(track);
    seg.addEventListener('click', () => { goTo(index); if (!reduced) play(); });
    fill.addEventListener('animationend', () => {
      if (index !== player.scene || player.paused || reduced) return;
      if (index + 1 < EX_DURATIONS.length) goTo(index + 1);
      else finish();
    });
    segs.appendChild(seg);
    return seg;
  });

  function setIcon(name, key) {
    playBtn.replaceChildren(iconEl(name));
    playBtn.dataset.i18nAria = key;
    playBtn.setAttribute('aria-label', t(key));
    playBtn.setAttribute('title', t(key));
  }

  function goTo(index) {
    player.scene = index;
    player.ended = false;
    wrap.classList.remove('ended');
    for (let k = 1; k <= EX_DURATIONS.length; k++) wrap.classList.remove('scene-' + k);
    fills.forEach(seg => seg.classList.remove('active'));
    void wrap.offsetWidth; // restart this scene's keyframes and the progress fill
    wrap.classList.add('scene-' + (index + 1));
    Object.entries(EX_TRACK).forEach(([name, track]) => {
      const el = actors[name];
      if (!el) return;
      const state = { x: 0, y: 0, s: 1, o: 1, ...track[index] };
      el.style.transform = 'translate(' + state.x + 'px, ' + state.y + 'px) scale(' + state.s + ')';
      el.style.opacity = String(state.o);
    });
    step.textContent = (index + 1) + ' / ' + EX_DURATIONS.length;
    setText(title, 'EX_S' + (index + 1) + '_T');
    setText(tech, 'EX_S' + (index + 1) + '_D', index === 2 ? explainerPowVars() : null);
    caption.classList.remove('swap');
    void caption.offsetWidth;
    caption.classList.add('swap');
    fills.forEach((seg, k) => {
      seg.classList.toggle('done', k < index);
      seg.classList.toggle('active', k === index);
    });
  }

  function pause() {
    player.paused = true;
    wrap.classList.add('paused');
    if (!player.ended) setIcon('play', 'EX_PLAY');
  }

  function play() {
    if (reduced) {
      goTo((player.scene + 1) % EX_DURATIONS.length);
      return;
    }
    explainers.forEach(other => { if (other !== player) other.pause(); });
    if (player.ended) goTo(0);
    player.paused = false;
    wrap.classList.remove('paused');
    setIcon('pause', 'EX_PAUSE');
  }

  function finish() {
    player.ended = true;
    player.paused = true;
    wrap.classList.add('ended');
    setIcon('replay', 'EX_REPLAY');
  }

  Object.assign(player, { goTo, pause, play, wrap });
  playBtn.addEventListener('click', () => (player.paused ? play() : pause()));
  frame.addEventListener('click', () => (player.paused ? play() : pause()));
  explainers.add(player);
  goTo(0);
  if (reduced) {
    wrap.classList.add('paused');
    setIcon('play', 'EX_PLAY');
  } else {
    setIcon('pause', 'EX_PAUSE');
  }
  msg.player = player;
  return msg;
}

function renderHelp() {
  const msg = addMessage('bot');
  msg.bubble.appendChild(i18nEl('p', '', 'HELP_TITLE')).classList.add('strong');
  const list = h('div', 'cmd-list');
  COMMANDS.forEach(cmd => {
    list.appendChild(h('code', '', cmd.usage));
    list.appendChild(i18nEl('span', '', cmd.key));
  });
  msg.bubble.appendChild(list);
  msg.bubble.appendChild(i18nEl('p', 'note-hint', 'HELP_LINK'));
  msg.bubble.appendChild(i18nHtmlEl('p', 'note-hint', 'HELP_KEYS'));
  return msg;
}

function clearChat() {
  explainers.forEach(player => player.pause());
  explainers.clear();
  openedNotes.forEach(opened => { wipeNote(opened.note); opened.urls.forEach(revokeUrl); });
  openedNotes.clear();
  objectUrls.forEach(revokeUrl);
  objectUrls.clear();
  $('chatLog').replaceChildren();
  messageCount = 0;
  gate = null;
  updateHero();
}

/* ══════════════════════════════════════════════════════
   Composer
   ══════════════════════════════════════════════════════ */
const COMMANDS = [
  { name: '/faq', usage: '/faq', key: 'CMD_FAQ' },
  { name: '/help', usage: '/help', key: 'CMD_HELP' },
  { name: '/clear', usage: '/clear', key: 'CMD_CLEAR' },
  { name: '/open', usage: '/open <link>', key: 'CMD_OPEN', arg: true },
];

// Only known commands are intercepted; anything else that starts with "/" is a secret.
function parseCommand(text) {
  const match = /^\/(faq|help|clear|open)(?:\s+([\s\S]*))?$/i.exec(String(text).trim());
  if (!match) return null;
  return { name: '/' + match[1].toLowerCase(), arg: (match[2] || '').trim() };
}

async function runCommand(cmd) {
  if (cmd.name === '/clear') {
    clearChat();
    return;
  }
  const userMsg = addMessage('user');
  userMsg.bubble.appendChild(h('div', 'bubble-text mono', cmd.name === '/open' ? '/open' : cmd.name));
  const reply = addTyping(null);
  await delay(380);
  reply.remove();
  if (cmd.name === '/faq') renderFaq();
  else if (cmd.name === '/help') renderHelp();
  else if (cmd.name === '/open') {
    if (!cmd.arg) { addBotNotice('ERR_OPEN_USAGE', null, 'warn'); return; }
    try {
      await openSharedLink(cmd.arg);
    } catch (err) {
      addBotNotice('ERR_GENERIC', { message: String(err.message || 'error') }, 'error');
    }
  }
}

function composerFiles() {
  return attachments.map(item => item.file);
}

function updateCharMeter() {
  const el = $('charTxt');
  const n = plaintextByteLength($('noteInput').value);
  const ratio = n / maxPlaintextBytes;
  el.classList.toggle('warn', ratio > 0.9 && ratio <= 1);
  el.classList.toggle('err', ratio > 1);
  el.textContent = ratio >= 0.5 ? formatBytes(n) + ' / ' + formatBytes(maxPlaintextBytes) : '';
}

function canSendCurrentCompose() {
  if (createInFlight) return false;
  const text = $('noteInput').value;
  const files = composerFiles();
  if (!text.trim() && !files.length) return false;
  if (parseCommand(text)) return true;
  if (plaintextByteLength(text) > maxPlaintextBytes) return false;
  return true;
}

function updateSendAvailability() {
  const btn = $('sendBtn');
  btn.disabled = !canSendCurrentCompose();
  btn.classList.toggle('busy', createInFlight);
}

function autosizeComposer() {
  const input = $('noteInput');
  if (!input.style) return;
  input.style.height = 'auto';
  if (input.scrollHeight) input.style.height = input.scrollHeight + 'px';
}

function renderAttachments() {
  const list = $('attachList');
  list.replaceChildren();
  attachments.forEach(item => {
    list.appendChild(fileChip(cleanFileName(item.file.name), item.file.size, () => {
      attachments = attachments.filter(other => other.id !== item.id);
      renderAttachments();
      $('noteInput').focus();
    }));
  });
  list.hidden = attachments.length === 0;
  updateHero();
  updateSendAvailability();
}

function addFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (maxFileBytes <= 0) {
    addBotNotice('ERR_FILES_DISABLED', null, 'warn');
    return;
  }
  let total = attachments.reduce((sum, item) => sum + item.file.size, 0);
  for (const file of files) {
    if (attachments.length >= MAX_FILES) {
      addBotNotice('ERR_FILES_TOO_MANY', { count: MAX_FILES }, 'warn');
      break;
    }
    if (total + file.size > maxFileBytes) {
      addBotNotice('ERR_FILES_TOO_LARGE', { size: formatBytes(total + file.size), limit: formatBytes(maxFileBytes) }, 'warn');
      continue;
    }
    total += file.size;
    attachments.push({ id: ++attachSeq, file });
  }
  renderAttachments();
}

function updateComposerLimits() {
  const attachBtn = $('attachBtn');
  if (attachBtn) attachBtn.hidden = maxFileBytes <= 0;
  if (maxFileBytes <= 0 && attachments.length) {
    attachments = [];
    renderAttachments();
  }
  updateDropZoneText();
  updateCharMeter();
  updateSendAvailability();
}

function updateDropZoneText() {
  const zone = $('dropZone');
  if (!zone) return;
  zone.classList.toggle('disabled', maxFileBytes <= 0);
  if (maxFileBytes > 0) {
    setText($('dropTitle'), 'DROP_TITLE');
    setText($('dropSub'), 'DROP_SUB', { limit: formatBytes(maxFileBytes) });
  } else {
    setText($('dropTitle'), 'DROP_DISABLED');
    $('dropSub').textContent = '';
    delete $('dropSub').dataset.i18n;
  }
}

function updateTtlChip() {
  const label = $('ttlChipLbl');
  if (!label) return;
  let ttl = 43200;
  try { ttl = selectedTtl(); } catch {}
  setText(label, ttlLabelKey(ttl));
}

function setTtl(value) {
  document.querySelectorAll('input[name="ttl"]').forEach(input => { input.checked = input.value === String(value); });
  storageSet(LS_TTL_KEY, String(value));
  updateTtlChip();
}

function clearComposer() {
  $('noteInput').value = '';
  attachments = [];
  renderAttachments();
  hideCmdMenu();
  autosizeComposer();
  updateCharMeter();
  updateSendAvailability();
}

function restoreComposer(text, files) {
  if ($('noteInput').value || attachments.length) return;
  $('noteInput').value = text;
  attachments = files.map(file => ({ id: ++attachSeq, file }));
  renderAttachments();
  autosizeComposer();
  updateCharMeter();
  updateSendAvailability();
}

/* ── Slash-command menu ── */
function hideCmdMenu() {
  cmdMenuItems = [];
  const menu = $('cmdMenu');
  menu.classList.add('hidden');
  menu.replaceChildren();
}

function isCmdMenuOpen() {
  return cmdMenuItems.length > 0;
}

function renderCmdMenu() {
  const menu = $('cmdMenu');
  menu.replaceChildren();
  cmdMenuItems.forEach((cmd, index) => {
    const item = h('button', 'cmd-item' + (index === cmdMenuIndex ? ' active' : ''));
    item.type = 'button';
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', index === cmdMenuIndex ? 'true' : 'false');
    item.appendChild(h('code', '', cmd.usage));
    item.appendChild(i18nEl('span', '', cmd.key));
    item.addEventListener('mousedown', event => { event.preventDefault(); completeCommand(cmd); });
    menu.appendChild(item);
  });
  menu.classList.toggle('hidden', cmdMenuItems.length === 0);
}

function updateCmdMenu() {
  const value = $('noteInput').value;
  if (!/^\/[a-z]*$/i.test(value)) {
    hideCmdMenu();
    return;
  }
  const prefix = value.toLowerCase();
  cmdMenuItems = COMMANDS.filter(cmd => cmd.name.startsWith(prefix));
  cmdMenuIndex = 0;
  renderCmdMenu();
}

function completeCommand(cmd) {
  hideCmdMenu();
  if (cmd.arg) {
    $('noteInput').value = cmd.name + ' ';
    $('noteInput').focus();
    updateSendAvailability();
    return;
  }
  $('noteInput').value = cmd.name;
  submitComposer();
}

/* ── Sending ── */
function uploadTimeoutMs(bytes) {
  return 15000 + Math.ceil(bytes / 40000) * 1000;
}

function cancelledError() {
  return Object.assign(new Error('API changed while the note was being sent'), { cancelled: true });
}

// Encrypt → prove (Argon2id) → upload. Shared by the chat and the WebMCP tool.
async function createNote({ text, files = [], ttl, onProgress, onSolved }) {
  const base = apiBase();
  const version = powContextVersion;
  const isCurrent = () => powContextVersion === version && apiBase() === base;

  let init = await getPowInit('create');
  if (!isCurrent()) throw cancelledError();
  const { blob, keyB64, viewTokenB64 } = await encrypt(text, files);
  if (blob.length > maxBlobBytes) throw appError('ERR_TOO_LARGE');
  const payloadHash = await payloadHashCreate(ttl, blob);
  if (!isPowFresh(init)) {
    if (powCache.create === init) powCache.create = null;
    init = await getPowInit('create');
  }
  if (!isCurrent()) throw cancelledError();
  const nonce = await solvePoW({
    challenge: init.challenge,
    bits: init.bits,
    rounds: init.rounds,
    params: init.params,
    expiresAt: init.expiresAt,
    payloadHash,
  }, onProgress);
  if (!isCurrent()) throw cancelledError();
  if (powCache.create === init) powCache.create = null;
  const body = JSON.stringify({
    alg: 'aes-256-gcm',
    challenge: init.challenge,
    nonce,
    ttl,
    blob,
    view_token: viewTokenB64,
  });
  const request = fetchJson(apiEndpoint('/api/v1/notes', base), {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body,
  }, uploadTimeoutMs(body.length));
  if (onSolved) await onSolved();
  const { response, body: result } = await request;
  if (!isCurrent()) throw cancelledError();
  if (!response.ok || !result?.ok || !result?.nid) {
    throw responseError(response, result, 'failed to create note');
  }
  if (!NID_RE.test(result.nid)) throw new Error('invalid note id from server');
  return { nid: result.nid, keyB64 };
}

async function sendNote({ text, files }) {
  if (createInFlight) return;
  createInFlight = true;
  updateSendAvailability();
  const ttl = selectedTtl();
  const userMsg = addUserMessage(text, files);
  const reply = addTyping('STATUS_CHECKING');
  let attempt = 0;
  try {
    while (true) {
      try {
        const { nid, keyB64 } = await createNote({
          text, files, ttl,
          onProgress: (found, rounds) => reply.typing.setProgress(found, rounds),
          onSolved: async () => {
            await reply.typing.hold(900);
            reply.typing.setStatus('STATUS_HUMAN', { done: true });
            await delay(MIN_HUMAN_STATUS_MS);
            reply.typing.setStatus('STATUS_LINK');
          },
        });
        await reply.typing.hold(MIN_LINK_STATUS_MS);
        renderLinkReply(reply, { url: buildHostedShareUrl(nid, keyB64), nid });
        userMsg.mask();
        return;
      } catch (err) {
        const staleChallenge = ['invalid_challenge', 'challenge_expired'].includes(err?.code) || err?.expired;
        if (staleChallenge && attempt === 0 && !err?.cancelled) {
          attempt++;
          powCache.create = null;
          reply.typing.setStatus('STATUS_CHECKING');
          continue;
        }
        throw err;
      }
    }
  } catch (err) {
    if (err?.cancelled || err?.message === 'PoW initialization was invalidated') {
      reply.remove();
      userMsg.remove();
      restoreComposer(text, files);
      return;
    }
    powCache.create = null;
    if (err?.code === 'no_pubkey') {
      reply.remove();
      userMsg.remove();
      restoreComposer(text, files);
      showNoPubkeyModal();
      return;
    }
    showErrorIn(reply, err, () => {
      reply.remove();
      userMsg.remove();
      sendNote({ text, files });
    });
  } finally {
    createInFlight = false;
    updateSendAvailability();
  }
}

// A message that is nothing but a SecNote share link (this or another server) opens that note
// instead of being encrypted as a new secret. Any other text around the link sends it as a secret.
function sharedLinkFromText(text) {
  const value = String(text).trim();
  if (!/^https?:\/\/\S+$/i.test(value)) return null;
  try {
    parseSharedLink(value);
    return value;
  } catch {
    return null;
  }
}

async function submitComposer(event) {
  event?.preventDefault?.();
  if (createInFlight) return;
  const text = $('noteInput').value;
  const files = composerFiles();
  if (!text.trim() && !files.length) return;
  const cmd = parseCommand(text);
  if (cmd) {
    // Commands never consume attachments: only the command text leaves the composer.
    $('noteInput').value = '';
    hideCmdMenu();
    autosizeComposer();
    updateCharMeter();
    updateSendAvailability();
    await runCommand(cmd);
    return;
  }
  const link = files.length ? null : sharedLinkFromText(text);
  if (link) {
    $('noteInput').value = '';
    autosizeComposer();
    updateCharMeter();
    updateSendAvailability();
    try {
      await openSharedLink(link);
    } catch (err) {
      addBotNotice('ERR_GENERIC', { message: String(err.message || 'error') }, 'error');
    }
    return;
  }
  const bytes = plaintextByteLength(text);
  if (bytes > maxPlaintextBytes) {
    addBotNotice('ERR_TEXT_TOO_LARGE', { size: formatBytes(bytes), limit: formatBytes(maxPlaintextBytes) }, 'error');
    return;
  }
  clearComposer();
  await sendNote({ text, files });
}

$('composer').addEventListener('submit', submitComposer);
$('noteInput').addEventListener('focus', updateHero);
$('noteInput').addEventListener('blur', updateHero);
$('noteInput').addEventListener('input', () => {
  updateHero();
  autosizeComposer();
  updateCharMeter();
  updateCmdMenu();
  updateSendAvailability();
});
$('noteInput').addEventListener('keydown', event => {
  if (isCmdMenuOpen()) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      cmdMenuIndex = (cmdMenuIndex + step + cmdMenuItems.length) % cmdMenuItems.length;
      renderCmdMenu();
      return;
    }
    if (event.key === 'Tab' || (event.key === 'Enter' && !event.shiftKey)) {
      event.preventDefault();
      completeCommand(cmdMenuItems[cmdMenuIndex]);
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      hideCmdMenu();
      return;
    }
  }
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && event.keyCode !== 229) {
    event.preventDefault();
    submitComposer();
  }
});
$('noteInput').addEventListener('paste', event => {
  const files = event.clipboardData?.files;
  if (files && files.length) {
    event.preventDefault();
    addFiles(files);
  }
});
$('attachBtn').addEventListener('click', () => $('fileInput').click());
$('fileInput').addEventListener('change', () => {
  addFiles($('fileInput').files);
  $('fileInput').value = '';
});
$('ttlChip').addEventListener('click', () => setTtl(selectedTtl() === 43200 ? 86400 : 43200));
document.querySelectorAll('input[name="ttl"]').forEach(input => {
  input.addEventListener('change', () => setTtl(input.value));
});
document.querySelectorAll('[data-cmd]').forEach(chip => {
  chip.addEventListener('click', () => {
    const cmd = parseCommand(chip.dataset.cmd);
    if (cmd) runCommand(cmd);
  });
});

/* ── Drag & drop ── */
let dragDepth = 0;
function dragHasFiles(event) {
  return Array.from(event.dataTransfer?.types || []).includes('Files');
}
window.addEventListener('dragenter', event => {
  if (!dragHasFiles(event)) return;
  event.preventDefault();
  dragDepth++;
  $('dropZone').classList.remove('hidden');
});
window.addEventListener('dragover', event => {
  if (!dragHasFiles(event)) return;
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = maxFileBytes > 0 ? 'copy' : 'none';
});
window.addEventListener('dragleave', event => {
  if (!dragHasFiles(event)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) $('dropZone').classList.add('hidden');
});
window.addEventListener('drop', event => {
  if (!dragHasFiles(event)) return;
  event.preventDefault();
  dragDepth = 0;
  $('dropZone').classList.add('hidden');
  addFiles(event.dataTransfer.files);
});

/* ══════════════════════════════════════════════════════
   Recipient: one-time gate
   ══════════════════════════════════════════════════════ */
function renderGate() {
  const msg = addMessage('bot', 'warn');
  msg.bubble.appendChild(i18nEl('p', 'strong', 'GATE_TITLE'));
  msg.bubble.appendChild(i18nEl('p', 'note-hint', 'GATE_WARN'));
  const statusWrap = h('div', 'gate-status');
  const typing = createTyping(statusWrap);
  msg.bubble.appendChild(statusWrap);
  const actions = h('div', 'gate-actions');
  const revealBtn = actionButton('btn btn-danger', 'GATE_REVEAL', revealNote, 'flame');
  revealBtn.id = 'revealBtn';
  revealBtn.disabled = true;
  const cancelBtn = actionButton('btn btn-ghost', 'GATE_CANCEL', cancelGate);
  actions.appendChild(revealBtn);
  actions.appendChild(cancelBtn);
  msg.bubble.appendChild(actions);
  gate = { msg, typing, statusWrap, revealBtn, cancelBtn, actions, done: false };
  return gate;
}

function gateError(err, retry) {
  if (!gate) return;
  const g = gate;
  g.typing.hide();
  g.statusWrap.querySelectorAll('.gate-error').forEach(node => node.remove());
  const box = h('div', 'gate-error');
  const { key, vars } = describeError(err);
  box.appendChild(i18nEl('p', 'msg-error-text', key, vars));
  if (retry) box.appendChild(actionButton('btn btn-ghost btn-sm', 'RETRY', () => { box.remove(); retry(); }));
  g.statusWrap.appendChild(box);
}

function closeGate() {
  if (!gate) return;
  gate.done = true;
  gate.actions.remove();
  gate.statusWrap.remove();
}

function cancelGate() {
  if (!isGateVisible() || viewInFlight) return;
  closeGate();
  clearPowCache();
  curNid = '';
  curKey = '';
  history.replaceState(null, '', buildComposeUrl());
  addBotNotice('GATE_CANCELLED');
  offerApiSwitchBack();
}

function hostLabel(url) {
  return apiBase(url).replace(/^https?:\/\//, '');
}

// A link from another server switches this page to that server for the session. Once its note
// is handled, say so and offer the user's own server back, so new secrets don't leave silently.
function offerApiSwitchBack() {
  const saved = initialApiConfig();
  if (apiBase() === apiBase(saved.url)) return;
  const msg = addMessage('bot');
  msg.bubble.appendChild(i18nEl('p', '', 'SERVER_SWITCH_NOTICE', { host: hostLabel() }));
  const actions = h('div', 'link-actions');
  const back = actionButton('btn btn-ghost btn-sm', 'SERVER_SWITCH_BACK', () => {
    msg.remove();
    restoreSavedApi();
  });
  setText(back.querySelector('span'), 'SERVER_SWITCH_BACK', { host: hostLabel(saved.url) });
  actions.appendChild(back);
  msg.bubble.appendChild(actions);
}

function restoreSavedApi() {
  const saved = initialApiConfig();
  apiUrl = saved.url;
  setApiPubKey(saved.pubkeyB64);
  clearPowCache();
  resetServerLimits();
  apiReachable = false;
  apiLatencyMs = null;
  healthState = 'checking';
  renderHealth();
  history.replaceState(null, '', buildComposeUrl());
  startComposeWarmup();
}

function updateRevealAvailability() {
  if (!gate) return;
  gate.revealBtn.disabled = viewInFlight || !(presolvedViewNonce && apiPubKeyB64 && isPowFresh(powCache.view));
}

function clearUrlKey() {
  const cleanUrl = new URL(location.href);
  cleanUrl.hash = '';
  history.replaceState(null, '', cleanUrl.toString());
}

// The view proof is bound only to the note id, so it is solved while the recipient decides.
function startPresolveView() {
  if (!isGateVisible()) return;
  clearTimeout(viewRefreshTimer);
  presolvedViewNonce = null;
  updateRevealAvailability();
  const g = gate;
  g.statusWrap.querySelectorAll('.gate-error').forEach(node => node.remove());
  g.typing.setStatus('STATUS_CHECKING');

  const version = powContextVersion;
  const state = { nid: curNid, version };
  presolveViewState = state;
  const stale = () => presolveViewState !== state || powContextVersion !== version || gate !== g || !isGateVisible();
  const pending = (async () => {
    try {
      const init = await getPowInit('view');
      if (stale()) return null;
      scheduleViewPowRefresh(init.expiresAt);
      const payloadHash = await payloadHashView(state.nid);
      const nonce = await solvePoW({
        challenge: init.challenge,
        bits: init.bits,
        rounds: init.rounds,
        params: init.params,
        expiresAt: init.expiresAt,
        payloadHash,
      }, (found, rounds) => g.typing.setProgress(found, rounds));
      if (stale()) return null;
      presolvedViewNonce = nonce;
      g.typing.setStatus('STATUS_HUMAN', { done: true });
      updateRevealAvailability();
      return nonce;
    } catch (err) {
      if (presolveViewState === state && isGateVisible() && gate === g) {
        if (err?.code === 'no_pubkey') { showNoPubkeyModal(); }
        gateError(err, () => startPresolveView());
      }
      return null;
    } finally {
      if (presolveViewPromise === pending) presolveViewPromise = null;
      if (presolveViewState === state) presolveViewState = null;
    }
  })();

  presolveViewPromise = pending;
}

async function revealNote() {
  if (viewInFlight || !isGateVisible()) return;
  const init = isPowFresh(powCache.view) ? powCache.view : null;
  const nonce = presolvedViewNonce;
  if (!init || !nonce) return;

  const g = gate;
  const nid = curNid;
  const key = curKey;
  const base = apiBase();
  const version = powContextVersion;
  const isCurrent = () => powContextVersion === version && apiBase() === base && curNid === nid && gate === g && isGateVisible();

  viewInFlight = true;
  updateRevealAvailability();
  g.cancelBtn.disabled = true;
  g.typing.setStatus('STATUS_OPENING');

  try {
    const { response, body } = await fetchJson(
      apiEndpoint('/api/v1/notes/' + encodeURIComponent(nid) + '/view', base),
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          challenge: init.challenge,
          nonce,
          view_token: await viewTokenFromKey(key),
        }),
        maxResponseBytes: Math.max(maxBlobBytes, DEFAULT_MAX_BLOB_BYTES) + 4096,
      },
      uploadTimeoutMs(maxBlobBytes)
    );

    if (!isCurrent()) return;
    presolvedViewNonce = null;
    powCache.view = null;
    clearTimeout(viewRefreshTimer);
    viewRefreshTimer = null;

    if (response.status === 410) {
      closeGate();
      curKey = '';
      clearUrlKey();
      renderBurned();
      offerApiSwitchBack();
      return;
    }
    if (!response.ok || !body?.ok || typeof body.blob !== 'string') {
      throw responseError(response, body, 'failed to read note');
    }

    let note;
    try {
      note = await decrypt(body.blob, key);
    } catch {
      closeGate();
      curKey = '';
      clearUrlKey();
      addBotNotice('ERR_MALFORMED', null, 'error');
      offerApiSwitchBack();
      return;
    }
    if (!isCurrent()) { wipeNote(note); return; }
    curKey = '';
    clearUrlKey();
    closeGate();
    renderNote(note);
    offerApiSwitchBack();
  } catch (err) {
    if (!isCurrent()) return;
    presolvedViewNonce = null;
    powCache.view = null;
    clearTimeout(viewRefreshTimer);
    viewRefreshTimer = null;
    if (err?.code === 'no_pubkey') { showNoPubkeyModal(); }
    gateError(err, () => startPresolveView());
  } finally {
    viewInFlight = false;
    if (g === gate && !g.done) g.cancelBtn.disabled = false;
    updateRevealAvailability();
  }
}

/* ══════════════════════════════════════════════════════
   Warm-up, settings, dialogs
   ══════════════════════════════════════════════════════ */
// Checks the server and fetches a create challenge, which also tells us the server limits
// (text size, whether files are allowed). Failures show up in the health signal only.
async function startComposeWarmup() {
  const seq = ++composeWarmupSeq;
  const ok = await pingApi(apiUrl);
  if (seq !== composeWarmupSeq || !ok) return;
  try {
    await getPowInit('create');
  } catch (err) {
    if (seq !== composeWarmupSeq) return;
    if (err?.code === 'no_pubkey') setHealth('warn');
  }
}

function openSettings() {
  $('apiInp').placeholder = location.origin;
  $('apiInp').value = apiUrl;
  setServerFormOpen(false);
  renderHealth();
  const select = $('langSelect');
  if (select) select.value = currentLangCode;
  $('oSettings').classList.remove('hidden');
  setTimeout(() => $('closeSettings').focus(), 40);
  pingApi(apiUrl);
}

function closeSettings() {
  $('oSettings').classList.add('hidden');
}

function beginApiConfiguration() {
  apiConfigController?.abort();
  apiConfigController = new AbortController();
  return apiConfigController.signal;
}

$('healthBtn').addEventListener('click', openSettings);
$('cogBtn').addEventListener('click', openSettings);
$('closeSettings').addEventListener('click', closeSettings);
$('changeServerBtn').addEventListener('click', () => setServerFormOpen($('serverForm').hidden));
$('cancelSettings').addEventListener('click', () => setServerFormOpen(false));
$('oSettings').addEventListener('click', event => {
  if (event.target === $('oSettings')) closeSettings();
});
$('langSelect').addEventListener('change', () => loadLang($('langSelect').value, { persist: true }));

$('defaultBtn').addEventListener('click', () => {
  $('apiInp').value = DEFAULT_API;
  $('saveSettings').click();
});

$('saveSettings').addEventListener('click', async () => {
  const { urlStr: candidateUrl, pubkeyB64: candidatePubkey } = parseApiConfig(($('apiInp').value || '').trim() || DEFAULT_API);
  if (!isSafeApiTransport(candidateUrl)) {
    setReach('err', t('SETTINGS_API_INVALID'));
    return;
  }
  const normalizedCandidatePubkey = normalizePubkeyB64(candidatePubkey);
  if (candidatePubkey && !normalizedCandidatePubkey) {
    setReach('err', t('SETTINGS_KEY_INVALID'));
    return;
  }
  const nextApi = normalizeApiUrl(candidateUrl);
  setServerFormOpen(false);
  const signal = beginApiConfiguration();

  if (isExternalApi(nextApi)) {
    if (normalizedCandidatePubkey) {
      // Manual pubkey entered (url|pubkey) — trust directly without modal.
      setApiPubKey(normalizedCandidatePubkey);
      saveTrustedApi(nextApi, normalizedCandidatePubkey);
      confirmedApiUrl = nextApi;
    } else if (nextApi !== confirmedApiUrl) {
      const confirmed = await showApiConfirmModal(nextApi, null, signal);
      if (!confirmed || signal.aborted) return;
      confirmedApiUrl = nextApi;
      // apiPubKeyB64 already set inside showApiConfirmModal via setApiPubKey().
    }
  } else {
    setApiPubKey(normalizedCandidatePubkey || getTrustedPubkey(nextApi) || (nextApi === DEFAULT_API ? DEFAULT_API_PUBKEY : null));
    if (normalizedCandidatePubkey) saveTrustedApi(nextApi, normalizedCandidatePubkey);
  }

  const changed = nextApi !== apiUrl;
  apiUrl = nextApi;
  storageSet(LS_KEY, apiUrl);
  clearPowCache();
  if (changed) resetServerLimits();
  apiReachable = false;
  apiLatencyMs = null;
  healthState = 'checking';
  renderHealth();
  startComposeWarmup();
  if (isGateVisible()) startPresolveView();
});

/* ── Runtime placeholder replacement (privacy policy, JSON-LD) ── */
(() => {
  const host = location.host;
  const origin = location.origin;
  const email = 'legal@' + location.hostname;
  function repText(s) {
    return s.replace(/\[\[HOST_URL\]\]/g, origin)
            .replace(/\[\[HOST\]\]/g, host)
            .replace(/\[\[EMAIL\]\]/g, email);
  }
  function replacePlaceholders(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      node.nodeValue = repText(node.nodeValue);
    }
    root.querySelectorAll('[href],[title],[aria-label]').forEach(el => {
      ['href', 'title', 'aria-label'].forEach(attr => {
        if (el.hasAttribute(attr)) el.setAttribute(attr, repText(el.getAttribute(attr)));
      });
    });
  }
  document.querySelectorAll('script[type="application/ld+json"]').forEach(el => {
    el.textContent = repText(el.textContent);
  });
  const pp = $('oPP');
  if (pp) replacePlaceholders(pp);
})();

function openPP() {
  closeSettings();
  $('oPP').classList.remove('hidden');
  const notice = $('oPP').querySelector('.pp-notice');
  if (notice) {
    const isLocal = location.protocol === 'file:' || /^localhost(:\d+)?$/.test(location.hostname);
    const show = !isLocal && apiUrl !== normalizeApiUrl(location.origin);
    notice.classList.toggle('hidden', !show);
  }
}

function closePP() {
  $('oPP').classList.add('hidden');
}

$('ppBtnCompose').addEventListener('click', openPP);
$('closePP').addEventListener('click', closePP);
$('acceptPP').addEventListener('click', closePP);
$('oPP').addEventListener('click', event => {
  if (event.target === $('oPP')) closePP();
});

/* ── Keyboard ── */
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    closeSettings();
    closePP();
    hideCmdMenu();
  }
});

/* ── No-pubkey modal ── */
function showNoPubkeyModal() {
  $('oNoPubkey').classList.remove('hidden');
  setTimeout(() => $('noPubkeyClose').focus(), 40);
}

$('noPubkeyClose').addEventListener('click', () => {
  $('oNoPubkey').classList.add('hidden');
});

/* ── API confirm ── */
function isExternalApi(url = apiUrl) {
  const page = pageDefaultApi() || FALLBACK_DEFAULT_API;
  return normalizeApiUrl(url, page) !== page;
}

function showExternalApiWarningModal(url, signal = null) {
  if (signal?.aborted) return Promise.resolve(false);
  return new Promise(resolve => {
    $('apiConfirmUrl').textContent = url;
    $('oApiConfirm').classList.remove('hidden');
    const focusTimer = setTimeout(() => $('apiConfirmAccept').focus(), 40);

    let settled = false;
    function done(result) {
      if (settled) return;
      settled = true;
      clearTimeout(focusTimer);
      $('oApiConfirm').classList.add('hidden');
      $('apiConfirmAccept').removeEventListener('click', onAccept);
      $('apiConfirmReject').removeEventListener('click', onReject);
      document.removeEventListener('keydown', onKey);
      $('oApiConfirm').removeEventListener('click', onBackdrop);
      signal?.removeEventListener('abort', onAbort);
      resolve(result);
    }
    function onAccept() { done(true); }
    function onReject() { done(false); }
    function onKey(e) { if (e.key === 'Escape') done(false); }
    function onBackdrop(e) { if (e.target === $('oApiConfirm')) done(false); }
    function onAbort() { done(false); }

    $('apiConfirmAccept').addEventListener('click', onAccept);
    $('apiConfirmReject').addEventListener('click', onReject);
    document.addEventListener('keydown', onKey);
    $('oApiConfirm').addEventListener('click', onBackdrop);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

async function showApiConfirmModal(url, pinnedPubkeyB64 = null, signal = null) {
  if (signal?.aborted) return false;
  const normalizedUrl = normalizeApiUrl(url);
  const storedPubkey = normalizePubkeyB64(getTrustedPubkey(normalizedUrl));
  const pinnedPubkey = normalizePubkeyB64(pinnedPubkeyB64);

  // Auto-trust: already in trust store — verify pubkey against live /info.
  // User already accepted this API, so the request is justified without re-confirming.
  if (storedPubkey && (!pinnedPubkey || storedPubkey === pinnedPubkey)) {
    const verifiedPubkey = await fetchApiPubkey(normalizedUrl, storedPubkey, signal);
    if (signal?.aborted) return false;
    if (verifiedPubkey === storedPubkey) {
      setApiPubKey(storedPubkey);
      return true;
    }
    // Pubkey changed or /info unreachable — fall through to show modals.
  }

  // Step 1: external API warning — shown BEFORE any /info request for new APIs.
  const proceed = await showExternalApiWarningModal(normalizedUrl, signal);
  if (!proceed || signal?.aborted) return false;

  if (pinnedPubkey) {
    return await showPinnedApiTrustResult(normalizedUrl, pinnedPubkey, signal);
  }

  // Step 2: fetch now that user confirmed. This is deliberately unsigned for
  // new or changed keys; the next modal is the trust decision.
  const fetchedPubkey = await fetchApiPubkey(normalizedUrl, null, signal);
  if (signal?.aborted) return false;
  if (!fetchedPubkey) {
    showNoPubkeyModal();
    return false;
  }
  const referencePubkey = storedPubkey || pinnedPubkey;
  const keyChanged = !!referencePubkey && referencePubkey !== fetchedPubkey;
  const statusClass = keyChanged ? 'err' : 'warn';
  const statusText = keyChanged
    ? 'Public key differs from the key trusted before.'
    : 'No pin was supplied. Trust this public key only if this endpoint is expected.';

  return await showApiTrustModal({
    url: normalizedUrl,
    pubkey: fetchedPubkey,
    expectedPubkey: keyChanged ? referencePubkey : null,
    expectedLabel: 'Trusted key',
    statusClass,
    statusText,
    acceptLabel: keyChanged ? 'Trust new key →' : 'Trust & Add →',
    signal,
  });
}

async function showPinnedApiTrustResult(url, pinnedPubkey, signal = null) {
  if (signal?.aborted) return false;
  const normalizedUrl = normalizeApiUrl(url);
  const verifiedPubkey = await fetchApiPubkey(normalizedUrl, pinnedPubkey, signal);
  if (signal?.aborted) return false;
  if (verifiedPubkey === pinnedPubkey) {
    return await showApiTrustModal({
      url: normalizedUrl,
      pubkey: pinnedPubkey,
      expectedPubkey: pinnedPubkey,
      expectedLabel: 'Pinned key',
      statusClass: 'ok',
      statusText: 'Pinned public key matches this API.',
      acceptLabel: 'continue →',
      signal,
    });
  }

  const fetchedPubkey = await fetchApiPubkey(normalizedUrl, null, signal);
  if (signal?.aborted) return false;
  if (!fetchedPubkey) {
    showNoPubkeyModal();
    return false;
  }
  await showApiTrustModal({
    url: normalizedUrl,
    pubkey: fetchedPubkey,
    expectedPubkey: pinnedPubkey,
    expectedLabel: 'Pinned key',
    statusClass: 'err',
    statusText: 'Pinned public key does not match this API. The link may point to the wrong server or be intercepted.',
    allowTrust: false,
    signal,
  });
  return false;
}

// Returns a DocumentFragment with differing characters wrapped in <span class="key-diff">.
// Builds DOM nodes directly — never parses untrusted strings as HTML.
function keyDiffFragment(actual, expected) {
  const frag = document.createDocumentFragment();
  const len = Math.max(actual.length, expected.length);
  for (let i = 0; i < len; i++) {
    const ca = actual[i] ?? '';
    const ce = expected[i] ?? '';
    const node = ca !== ce ? Object.assign(document.createElement('span'), { className: 'key-diff', textContent: ca || '?' })
                           : document.createTextNode(ca);
    frag.appendChild(node);
  }
  return frag;
}

async function showApiTrustModal({
  url,
  pubkey,
  expectedPubkey = null,
  expectedLabel = 'Expected key',
  statusClass = 'warn',
  statusText = '',
  acceptLabel = 'Trust & Add →',
  allowTrust = true,
  signal = null,
}) {
  if (signal?.aborted) return false;
  const hasMismatch = expectedPubkey && pubkey && pubkey !== expectedPubkey;
  $('apiTrustUrl').textContent = url;
  const pubkeyEl = $('apiTrustPubkey');
  pubkeyEl.textContent = '';
  pubkeyEl.appendChild(hasMismatch ? keyDiffFragment(pubkey, expectedPubkey) : document.createTextNode(pubkey || '—'));
  $('apiTrustExpectedLabel').textContent = expectedLabel;
  const expectedEl = $('apiTrustExpected');
  expectedEl.textContent = '';
  expectedEl.appendChild(hasMismatch ? keyDiffFragment(expectedPubkey, pubkey) : document.createTextNode(expectedPubkey || ''));
  $('apiTrustExpectedRow').hidden = !expectedPubkey;
  $('apiTrustStatus').textContent = statusText;
  $('apiTrustStatus').className = 'trust-status ' + statusClass;
  $('apiTrustStatus').hidden = !statusText;
  $('apiTrustKeyWarn').hidden = true;
  $('apiTrustAccept').textContent = acceptLabel;
  $('apiTrustAccept').hidden = !allowTrust;
  $('oApiTrust').classList.remove('hidden');
  const focusTimer = setTimeout(() => (allowTrust ? $('apiTrustAccept') : $('apiTrustReject')).focus(), 40);

  return new Promise(resolve => {
    let settled = false;
    function done(trusted) {
      if (settled) return;
      settled = true;
      clearTimeout(focusTimer);
      $('oApiTrust').classList.add('hidden');
      $('apiTrustAccept').removeEventListener('click', onAccept);
      $('apiTrustReject').removeEventListener('click', onReject);
      document.removeEventListener('keydown', onKey);
      $('oApiTrust').removeEventListener('click', onBackdrop);
      signal?.removeEventListener('abort', onAbort);
      trusted = trusted && !signal?.aborted;
      if (trusted) {
        saveTrustedApi(url, pubkey);
        setApiPubKey(pubkey);
      }
      resolve(trusted);
    }
    function onAccept() { if (allowTrust) done(true); }
    function onReject() { done(false); }
    function onKey(e) { if (e.key === 'Escape') done(false); }
    function onBackdrop(e) { if (e.target === $('oApiTrust')) done(false); }
    function onAbort() { done(false); }

    $('apiTrustAccept').addEventListener('click', onAccept);
    $('apiTrustReject').addEventListener('click', onReject);
    document.addEventListener('keydown', onKey);
    $('oApiTrust').addEventListener('click', onBackdrop);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/* ══════════════════════════════════════════════════════
   Router
   ══════════════════════════════════════════════════════ */
function openGateForCurrentNote(errorKey) {
  renderGate();
  if (errorKey) gateError(appError(errorKey), null);
}

async function route() {
  const signal = beginApiConfiguration();
  clearPowCache();
  clearChat();
  curNid = '';
  curKey = '';
  const params = new URLSearchParams(location.search);
  const p = params.get('p');
  const key = location.hash.slice(1);
  const hasNote = !!(p && key && NID_RE.test(p) && KEY_RE.test(key));
  const apiP = params.get('api');
  const rawPin = params.get('pin');
  const parsedApi = parseApiConfig(apiP || '');
  const pinP = normalizePubkeyB64(parsedApi.pubkeyB64) || normalizePubkeyB64(rawPin);
  if ((rawPin && !normalizePubkeyB64(rawPin)) ||
      (parsedApi.pubkeyB64 && !normalizePubkeyB64(parsedApi.pubkeyB64)) ||
      (rawPin && parsedApi.pubkeyB64 && rawPin !== parsedApi.pubkeyB64) ||
      (apiP && !isSafeApiTransport(parsedApi.urlStr))) {
    clearPowCache();
    addBotNotice('ERR_LINK_PARAMS', null, 'error');
    startComposeWarmup();
    return;
  }

  const previousApi = apiUrl;
  if (apiP) {
    const { urlStr: apiPUrl, pubkeyB64: apiPKey } = parseApiConfig(apiP);
    if (isSafeApiTransport(apiPUrl)) {
      apiUrl = normalizeApiUrl(apiPUrl);
      setApiPubKey(apiPKey || pinP || getTrustedPubkey(apiUrl) || (apiUrl === DEFAULT_API ? DEFAULT_API_PUBKEY : null));
      clearPowCache();
    }
  } else if (p && key) {
    const hostedApi = hostedDefaultApi();
    if (hostedApi && hostedApi !== apiUrl) {
      apiUrl = hostedApi;
      setApiPubKey(getTrustedPubkey(apiUrl) || (apiUrl === DEFAULT_API ? DEFAULT_API_PUBKEY : null));
      clearPowCache();
    }
    if (pinP) setApiPubKey(pinP);
  }
  if (apiUrl !== previousApi) resetServerLimits();
  renderHealth();

  // A pin in a shared link is checked on every navigation, even for a previously confirmed origin.
  if (!isExternalApi() && pinP) {
    const confirmed = await showPinnedApiTrustResult(apiUrl, pinP, signal);
    if (signal.aborted) return;
    if (!confirmed) {
      if (hasNote) {
        curNid = p;
        curKey = key;
        openGateForCurrentNote('ERR_UNTRUSTED');
      }
      startComposeWarmup();
      return;
    }
    confirmedApiUrl = apiUrl;
  } else if (isExternalApi() && (apiUrl !== confirmedApiUrl || pinP)) {
    const hadPinnedApi = !!apiPubKeyB64;
    const confirmed = await showApiConfirmModal(apiUrl, apiPubKeyB64, signal);
    if (signal.aborted) return;
    if (!confirmed) {
      if (hadPinnedApi && hasNote) {
        curNid = p;
        curKey = key;
        openGateForCurrentNote('ERR_UNTRUSTED');
        startComposeWarmup();
        return;
      }
      apiUrl = hostedDefaultApi();
      setApiPubKey(getTrustedPubkey(apiUrl) || (apiUrl === DEFAULT_API ? DEFAULT_API_PUBKEY : null));
      storageSet(LS_KEY, '');
      clearPowCache();
      resetServerLimits();
      renderHealth();
      const cleanUrl = new URL(location.href);
      cleanUrl.searchParams.delete('api');
      cleanUrl.searchParams.delete('pin');
      history.replaceState(null, '', cleanUrl.toString());
    } else {
      confirmedApiUrl = apiUrl;
    }
  }

  if (hasNote) {
    curNid = p;
    curKey = key;
    renderGate();
    startComposeWarmup();
    startPresolveView();
  } else {
    startComposeWarmup();
  }
}

window.addEventListener('popstate', () => route());

/* ── Start ── */
try {
  const storedTtl = storageGet(LS_TTL_KEY, '');
  if (storedTtl === '43200' || storedTtl === '86400') setTtl(storedTtl);
} catch {}
route();
updateCharMeter();
updateComposerLimits();
loadLang(detectLang());
setInterval(() => {
  if (document.visibilityState !== 'hidden') pingApi(apiUrl);
}, HEALTH_INTERVAL_MS);

/* ── WebMCP: expose note creation to browser AI agents ── */
if (ENABLE_MODEL_CONTEXT_TOOLS && typeof navigator !== 'undefined' && navigator.modelContext) {
  navigator.modelContext.provideContext({
    tools: [{
      name: 'create_encrypted_note',
      description: 'Create a zero-knowledge encrypted one-time note. Encrypted client-side with AES-256-GCM. Returns a shareable link that can only be opened once, after which the note is permanently destroyed.',
      inputSchema: {
        type: 'object',
        properties: {
          text: {
            type: 'string',
            description: 'The text content to encrypt and send (max 32768 UTF-8 bytes by default).',
            maxLength: DEFAULT_MAX_PLAINTEXT_BYTES,
          },
          ttl: {
            type: 'integer',
            enum: [43200, 86400],
            description: 'Time-to-live in seconds: 43200 (12 hours) or 86400 (24 hours). Defaults to 86400.',
            default: 86400,
          },
        },
        required: ['text'],
      },
      execute: async ({ text, ttl = 86400 }) => {
        if (!text || !text.trim()) return { error: 'text is required' };
        if (plaintextByteLength(text) > maxPlaintextBytes) return { error: 'text exceeds ' + maxPlaintextBytes + ' bytes' };
        if (ttl !== 43200 && ttl !== 86400) return { error: 'ttl must be 43200 or 86400' };
        try {
          const { nid, keyB64 } = await createNote({ text, files: [], ttl });
          return {
            link: buildHostedShareUrl(nid, keyB64),
            note_id: nid,
            expires_in_hours: ttl / 3600,
          };
        } catch (err) {
          return { error: err.message || 'unknown error' };
        }
      },
    }],
  });
}

})();
