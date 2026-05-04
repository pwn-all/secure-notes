(function () {
'use strict';

/* ── Helpers ── */
const $ = id => document.getElementById(id);
const RING_PATH = 100;
const RUNTIME_CONFIG = window.SECNOTE_CONFIG || {};
const LOCAL_DEV_API = 'http://localhost';
const FALLBACK_DEFAULT_API = /^https?:$/.test(location.protocol) ? location.origin : LOCAL_DEV_API;
const ENABLE_MODEL_CONTEXT_TOOLS = RUNTIME_CONFIG.enableModelContextTools === true;
const DEFAULT_API = initialDefaultApi();
const DEFAULT_API_LABEL = String(RUNTIME_CONFIG.defaultApiLabel || 'Native API');
const DEFAULT_API_PUBKEY = typeof RUNTIME_CONFIG.defaultApiPubKey === 'string' ? (RUNTIME_CONFIG.defaultApiPubKey || null) : null;
const LS_KEY = 'sn_api';
const LS_TRUSTED_KEY = 'sn_trusted';
const POW_CHUNK = 250;
const POW_REFRESH_SKEW_MS = 5000;
const MAX_POW_BITS = 28;
const DEFAULT_MAX_PLAINTEXT_BYTES = 4096;
const MAX_RESPONSE_BYTES = 64 * 1024;
const POW_NONCE_BYTES = 8;
const AES_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const NID_RE = /^[A-Za-z0-9_-]{22}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{32}$/;
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
let createRefreshTimer = null;
let viewRefreshTimer = null;
let apiReachable = false;
let apiCheckSeq = 0;
let composeWarmupSeq = 0;
let maxPlaintextBytes = DEFAULT_MAX_PLAINTEXT_BYTES;
let confirmedApiUrl = null;

/* ── i18n ── */
const LS_LANG_KEY = 'sn_lang';
const RTL_LANGS = new Set(['ar', 'ur']);
const BUILTIN_I18N = {
  en: {
    APP_PREPARE: 'Preparing...',
    APP_GET_ANTIBOT: 'Getting challenge...',
    POW_SOLVING: 'Wait. Solving anti-bot...',
    APP_READY: 'Ready',
    APP_SENDING: 'Sending...',
    APP_DONE: 'Done',
    READY_TO_SAVE: 'Ready to save note',
    SETTINGS_CHECKING: 'checking…',
    SETTINGS_REACHABLE: 'reachable',
    SETTINGS_UNREACHABLE: 'unreachable',
  },
  de: {
    APP_PREPARE: 'Vorbereitung...',
    APP_GET_ANTIBOT: 'Challenge wird geladen...',
    POW_SOLVING: 'Bitte warten. Anti-Bot wird gelost...',
    APP_READY: 'Bereit',
    APP_SENDING: 'Senden...',
    APP_DONE: 'Fertig',
    READY_TO_SAVE: 'Bereit zum Speichern',
    SETTINGS_CHECKING: 'Prüfen…',
    SETTINGS_REACHABLE: 'Erreichbar',
    SETTINGS_UNREACHABLE: 'Nicht erreichbar',
  },
  es: {
    APP_PREPARE: 'Preparando...',
    APP_GET_ANTIBOT: 'Obteniendo challenge...',
    POW_SOLVING: 'Espera. Resolviendo anti-bot...',
    APP_READY: 'Listo',
    APP_SENDING: 'Enviando...',
    APP_DONE: 'Hecho',
    READY_TO_SAVE: 'Listo para guardar',
    SETTINGS_CHECKING: 'comprobando…',
    SETTINGS_REACHABLE: 'accesible',
    SETTINGS_UNREACHABLE: 'inaccesible',
  },
  fr: {
    APP_PREPARE: 'Preparation...',
    APP_GET_ANTIBOT: 'Recuperation du challenge...',
    POW_SOLVING: 'Attendez. Resolution anti-bot...',
    APP_READY: 'Pret',
    APP_SENDING: 'Envoi...',
    APP_DONE: 'Termine',
    READY_TO_SAVE: 'Pret a sauvegarder',
    SETTINGS_CHECKING: 'vérification…',
    SETTINGS_REACHABLE: 'accessible',
    SETTINGS_UNREACHABLE: 'inaccessible',
  },
  pt: {
    APP_PREPARE: 'Preparando...',
    APP_GET_ANTIBOT: 'Obtendo challenge...',
    POW_SOLVING: 'Aguarde. Resolvendo anti-bot...',
    APP_READY: 'Pronto',
    APP_SENDING: 'Enviando...',
    APP_DONE: 'Concluido',
    READY_TO_SAVE: 'Pronto para salvar',
    SETTINGS_CHECKING: 'verificando…',
    SETTINGS_REACHABLE: 'acessível',
    SETTINGS_UNREACHABLE: 'inacessível',
  },
  ru: {
    APP_PREPARE: 'Подготовка...',
    APP_GET_ANTIBOT: 'Получаем challenge...',
    POW_SOLVING: 'Подождите. Решаем анти-бот проверку...',
    APP_READY: 'Готово',
    APP_SENDING: 'Отправка...',
    APP_DONE: 'Готово',
    READY_TO_SAVE: 'Готово к сохранению',
    SETTINGS_CHECKING: 'проверяем…',
    SETTINGS_REACHABLE: 'доступен',
    SETTINGS_UNREACHABLE: 'недоступен',
  },
  ua: {
    APP_PREPARE: 'Підготовка...',
    APP_GET_ANTIBOT: 'Отримуємо challenge...',
    POW_SOLVING: 'Зачекайте. Розвʼязуємо анти-бот перевірку...',
    APP_READY: 'Готово',
    APP_SENDING: 'Надсилання...',
    APP_DONE: 'Готово',
    READY_TO_SAVE: 'Готово до збереження',
    SETTINGS_CHECKING: 'перевіряємо…',
    SETTINGS_REACHABLE: 'доступний',
    SETTINGS_UNREACHABLE: 'недоступний',
  },
  ar: {
    APP_PREPARE: 'جار التحضير...',
    APP_GET_ANTIBOT: 'جار جلب التحدي...',
    POW_SOLVING: 'انتظر. جار حل التحقق المضاد للبوت...',
    APP_READY: 'جاهز',
    APP_SENDING: 'جار الإرسال...',
    APP_DONE: 'تم',
    READY_TO_SAVE: 'جاهز لحفظ الملاحظة',
    SETTINGS_CHECKING: 'جار التحقق…',
    SETTINGS_REACHABLE: 'متاح',
    SETTINGS_UNREACHABLE: 'غير متاح',
  },
  bn: {
    APP_PREPARE: 'প্রস্তুতি চলছে...',
    APP_GET_ANTIBOT: 'চ্যালেঞ্জ আনা হচ্ছে...',
    POW_SOLVING: 'অপেক্ষা করুন। অ্যান্টি-বট যাচাই সমাধান করা হচ্ছে...',
    APP_READY: 'প্রস্তুত',
    APP_SENDING: 'পাঠানো হচ্ছে...',
    APP_DONE: 'সম্পন্ন',
    READY_TO_SAVE: 'নোট সংরক্ষণের জন্য প্রস্তুত',
    SETTINGS_CHECKING: 'যাচাই করা হচ্ছে…',
    SETTINGS_REACHABLE: 'পৌঁছানো যায়',
    SETTINGS_UNREACHABLE: 'পৌঁছানো যাচ্ছে না',
  },
  cn: {
    APP_PREPARE: '准备中...',
    APP_GET_ANTIBOT: '正在获取 challenge...',
    POW_SOLVING: '请稍候。正在完成防机器人验证...',
    APP_READY: '就绪',
    APP_SENDING: '发送中...',
    APP_DONE: '完成',
    READY_TO_SAVE: '准备保存笔记',
    SETTINGS_CHECKING: '检查中…',
    SETTINGS_REACHABLE: '可访问',
    SETTINGS_UNREACHABLE: '无法访问',
  },
  hi: {
    APP_PREPARE: 'तैयारी...',
    APP_GET_ANTIBOT: 'challenge प्राप्त किया जा रहा है...',
    POW_SOLVING: 'रुकें। एंटी-बॉट जांच हल की जा रही है...',
    APP_READY: 'तैयार',
    APP_SENDING: 'भेजा जा रहा है...',
    APP_DONE: 'पूरा',
    READY_TO_SAVE: 'नोट सहेजने के लिए तैयार',
    SETTINGS_CHECKING: 'जांच हो रही है…',
    SETTINGS_REACHABLE: 'पहुंच योग्य',
    SETTINGS_UNREACHABLE: 'अनुपलब्ध',
  },
  ur: {
    APP_PREPARE: 'تیاری...',
    APP_GET_ANTIBOT: 'challenge حاصل کیا جا رہا ہے...',
    POW_SOLVING: 'انتظار کریں۔ اینٹی بوٹ تصدیق حل کی جا رہی ہے...',
    APP_READY: 'تیار',
    APP_SENDING: 'بھیجا جا رہا ہے...',
    APP_DONE: 'مکمل',
    READY_TO_SAVE: 'نوٹ محفوظ کرنے کے لیے تیار',
    SETTINGS_CHECKING: 'جانچ ہو رہی ہے…',
    SETTINGS_REACHABLE: 'قابل رسائی',
    SETTINGS_UNREACHABLE: 'ناقابل رسائی',
  },
};
const SUPPORTED_LANGS = new Set(Object.keys(BUILTIN_I18N));
let currentLangCode = normalizeLangCode(storageGet(LS_LANG_KEY, 'en'));
let langStrings = {};
let enStrings = null;
let langLoadSeq = 0;

function normalizeLangCode(code) {
  const value = String(code || '').toLowerCase();
  return SUPPORTED_LANGS.has(value) ? value : 'en';
}

function sanitizeLangMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out = {};
  Object.entries(value).forEach(([key, val]) => {
    if (typeof key === 'string' && typeof val === 'string') out[key] = val.slice(0, 5000);
  });
  return out;
}

async function ensureEnStrings() {
  if (enStrings !== null) return;
  try {
    const res = await fetch('langs/en.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    enStrings = res.ok ? sanitizeLangMap(await res.json()) : {};
  } catch { enStrings = {}; }
}

async function loadLang(code) {
  code = normalizeLangCode(code);
  const seq = ++langLoadSeq;
  await ensureEnStrings();
  if (seq !== langLoadSeq) return;
  currentLangCode = code;
  if (code !== 'en') {
    try {
      const res = await fetch('langs/' + encodeURIComponent(code) + '.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (res.ok) langStrings = sanitizeLangMap(await res.json());
      else langStrings = {};
    } catch { langStrings = {}; }
  } else {
    langStrings = {};
  }
  if (seq !== langLoadSeq) return;
  applyLang();
  storageSet(LS_LANG_KEY, code);
  $('langCode').textContent = code;
  document.querySelectorAll('#langMenu [data-lang]').forEach(li => {
    li.setAttribute('aria-selected', li.dataset.lang === code ? 'true' : 'false');
  });
  document.documentElement.dir = RTL_LANGS.has(code) ? 'rtl' : 'ltr';
  const langMap = { ua: 'uk', cn: 'zh' };
  document.documentElement.lang = langMap[code] || code;
}

const SAFE_I18N_TAGS = new Set(['b', 'strong', 'em', 'i', 'br', 'code', 'span']);
function sanitizedI18nFragment(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String(html || '');
  (function clean(node) {
    Array.from(node.childNodes).forEach(child => {
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
function applyLang() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const val = langStrings[el.dataset.i18n] || (enStrings && enStrings[el.dataset.i18n]);
    if (typeof val === 'string') el.textContent = val;
  });
  document.querySelectorAll('[data-i18n-html]').forEach(el => {
    const val = langStrings[el.dataset.i18nHtml] || (enStrings && enStrings[el.dataset.i18nHtml]);
    if (typeof val === 'string') el.replaceChildren(sanitizedI18nFragment(val));
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    const val = langStrings[el.dataset.i18nPh] || (enStrings && enStrings[el.dataset.i18nPh]);
    if (typeof val === 'string') el.placeholder = val;
  });
  updateDynamicStatusLabels();
  requestAnimationFrame(fitSquigs);
}

/* ── i18n lookup ── */
function t(key) {
  return (
    (langStrings && langStrings[key]) ||
    (BUILTIN_I18N[currentLangCode] && BUILTIN_I18N[currentLangCode][key]) ||
    (enStrings && enStrings[key]) ||
    (BUILTIN_I18N.en && BUILTIN_I18N.en[key]) ||
    key
  );
}

function updateDynamicStatusLabels() {
  document.querySelectorAll('[data-status-key]').forEach(el => {
    const key = el.dataset.statusKey;
    if (key) el.textContent = t(key);
  });
  document.querySelectorAll('[data-pow-solving="true"] .pow-solving-txt').forEach(span => {
    span.textContent = t('POW_SOLVING');
  });
}

/* ── PoW UI helpers ── */
function resetStatusEl(el, baseClass, text = '', extraClass = '') {
  delete el.dataset.powSolving;
  delete el.dataset.statusKey;
  el.className = extraClass ? baseClass + ' ' + extraClass : baseClass;
  el.textContent = text;
}

function setTranslatedStatusEl(el, baseClass, key, extraClass = '') {
  resetStatusEl(el, baseClass, t(key), extraClass);
  el.dataset.statusKey = key;
}

function showPowSolvingMsg(el, baseClass) {
  el.dataset.powSolving = 'true';
  el.className = baseClass + ' pow-solving';
  el.replaceChildren();
  const span = document.createElement('span');
  span.className = 'pow-solving-txt';
  span.textContent = t('POW_SOLVING');
  const spin = document.createElement('span');
  spin.className = 'spin';
  spin.setAttribute('aria-hidden', 'true');
  el.appendChild(span);
  el.appendChild(spin);
}

function startPowPulse(el) {
  el.classList.remove('pow-pulse');
  void el.offsetWidth;
  el.classList.add('pow-pulse');
}

/* ── Squig sizing ── */
function wavePath(w) {
  let d = 'M0,5';
  for (let x = 0; x + 20 <= w; x += 20) {
    const cy = (x / 20) % 2 === 0 ? 1 : 9;
    d += ` Q${x + 10},${cy} ${x + 20},5`;
  }
  const rem = w % 20;
  if (rem > 5) {
    const base = w - rem;
    const cy = (base / 20) % 2 === 0 ? 1 : 9;
    d += ` Q${base + rem / 2},${cy} ${w},5`;
  }
  return d;
}

function fitSquigs() {
  document.querySelectorAll('.squig').forEach(svg => {
    const prev = svg.previousElementSibling;
    if (!prev) return;
    const heading = prev.matches('.h1,.h2') ? prev : prev.querySelector('.h1,.h2');
    if (!heading) return;
    const range = document.createRange();
    range.selectNodeContents(heading);
    const w = Math.ceil(range.getBoundingClientRect().width);
    if (w <= 0) return;
    svg.setAttribute('width', w);
    svg.setAttribute('viewBox', `0 0 ${w} 10`);
    const path = svg.querySelector('path');
    if (path) path.setAttribute('d', wavePath(w));
  });
}

/* ── Screen switcher ── */
const SCREENS = ['sCompose', 'sLink', 'sGate', 'sRead', 'sBurned'];
function show(id) {
  SCREENS.forEach(s => $(s).classList.toggle('hidden', s !== id));
  $('howSection').classList.toggle('hidden', id !== 'sCompose');
  requestAnimationFrame(fitSquigs);
}

/* ── How it works tabs ── */
function switchTab(active) {
  ['Simple', 'Tech'].forEach(name => {
    const tab = $('tab' + name);
    const panel = $('panel' + name);
    const on = name === active;
    tab.classList.toggle('active', on);
    tab.setAttribute('aria-selected', on);
    panel.classList.toggle('hidden', !on);
  });
}
$('tabSimple').addEventListener('click', () => switchTab('Simple'));
$('tabTech').addEventListener('click', () => switchTab('Tech'));

/* ── API helpers ── */
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

function getTrustedApis() {
  try { return JSON.parse(storageGet(LS_TRUSTED_KEY, '{}')); } catch { return {}; }
}
function getTrustedPubkey(url) {
  const map = getTrustedApis();
  const key = normalizeApiUrl(url);
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
}
function saveTrustedApi(url, pubkey) {
  const map = getTrustedApis();
  map[normalizeApiUrl(url)] = pubkey ?? '';
  try { localStorage.setItem(LS_TRUSTED_KEY, JSON.stringify(map)); } catch {}
}

async function fetchApiPubkey(baseUrl) {
  try {
    const { response, body } = await fetchJson(
      new URL('/info', baseUrl + '/').toString(),
      { headers: { Accept: 'application/json' }, allowUnsigned: true },
      4000
    );
    if (!response.ok || !body?.ok) return null;
    return typeof body.pubkey === 'string' ? (body.pubkey || '') : '';
  } catch { return null; }
}

function isLoopbackHostname(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === 'localhost' ||
    host === '[::1]' ||
    host === '::1' ||
    /^127(?:\.\d{1,3}){3}$/.test(host);
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
  const pubkey = trusted !== null ? (trusted || null) : (pubkeyB64 || DEFAULT_API_PUBKEY);
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

function setApiQueryParam(url, api) {
  const pageApi = pageDefaultApi(url);
  const normalizedApi = isSafeApiTransport(api) ? normalizeApiUrl(api, pageApi || DEFAULT_API) : (pageApi || DEFAULT_API);
  url.searchParams.delete('api');
  if (!pageApi || normalizedApi !== pageApi) {
    url.searchParams.set('api', normalizedApi);
  }
}

function apiBase(url = apiUrl) {
  return normalizeApiUrl(url, hostedDefaultApi());
}

function apiEndpoint(path, base = apiUrl) {
  return new URL(path, apiBase(base)).toString();
}

function clearPowCache() {
  powContextVersion++;
  clearTimeout(createRefreshTimer);
  clearTimeout(viewRefreshTimer);
  powCache.create = null;
  powCache.view = null;
  powInitPromises.create = null;
  powInitPromises.view = null;
  presolvedViewNonce = null;
  presolveViewPromise = null;
  presolveViewState = null;
  createRefreshTimer = null;
  viewRefreshTimer = null;
}

function isPowFresh(entry) {
  return !!entry && entry.expiresAt * 1000 > Date.now() + POW_REFRESH_SKEW_MS;
}

function isComposeVisible() {
  return !$('sCompose').classList.contains('hidden');
}

function isGateVisible() {
  return !$('sGate').classList.contains('hidden');
}

function selectedTtl() {
  return +document.querySelector('input[name="ttl"]:checked').value;
}

function plaintextByteLength(text) {
  return te.encode(text).length;
}

function canSendCurrentCompose() {
  const text = $('noteInput').value;
  if (!text.trim()) return false;
  if (plaintextByteLength(text) > maxPlaintextBytes) return false;
  return !!(apiReachable && apiPubKeyB64 && isPowFresh(powCache.create));
}

function updateSendAvailability() {
  $('sendBtn').disabled = !canSendCurrentCompose();
}

function canRevealCurrentGate() {
  return !!(presolvedViewNonce && apiPubKeyB64 && isPowFresh(powCache.view));
}

function updateRevealAvailability() {
  $('revealBtn').disabled = !canRevealCurrentGate();
}

function scheduleCreatePowRefresh(expiresAt) {
  clearTimeout(createRefreshTimer);
  if (!expiresAt) return;
  const delay = Math.max(1000, expiresAt * 1000 - Date.now() - POW_REFRESH_SKEW_MS);
  createRefreshTimer = setTimeout(() => {
    createRefreshTimer = null;
    if (!isComposeVisible()) return;
    powCache.create = null;
    startComposeWarmup();
  }, delay);
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

function updateApiDisplay(url) {
  const base = apiBase(url);
  $('apiHost').textContent = base === hostedDefaultApi() ? DEFAULT_API_LABEL : base.replace(/^https?:\/\//, '');
}

function setDot(state) {
  const dot = $('apiDot');
  dot.classList.remove('ok', 'err');
  if (state !== 'idle') dot.classList.add(state);
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

async function readLimitedText(response, maxBytes = MAX_RESPONSE_BYTES) {
  const cl = response.headers.get('content-length');
  if (cl && Number.parseInt(cl, 10) > maxBytes) throw new Error('response too large');

  if (!response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (te.encode(text).length > maxBytes) throw new Error('response too large');
    return text;
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
  return td.decode(bytes);
}

async function fetchJson(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      signal: controller.signal,
    });
    const text = await readLimitedText(response);

    if (apiPubKeyB64) {
      const sigB64 = response.headers.get('x-secnote-sig');
      if (!sigB64) throw new Error('response signature missing');
      const sigBytes = fromb64u(sigB64, 64, 'response signature');
      if (!apiVerifyKey) await loadVerifyKey(apiPubKeyB64);
      const valid = await crypto.subtle.verify({ name: 'Ed25519' }, apiVerifyKey, sigBytes, te.encode(text));
      if (!valid) throw new Error('response signature invalid');
    } else if (!options.allowUnsigned) {
      throw Object.assign(new Error('server signing key not configured'), { code: 'no_pubkey' });
    }

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
    if (err && err.name === 'AbortError') throw new Error('request timed out');
    throw err;
  } finally {
    clearTimeout(timer);
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
  return err;
}

function updateServerInfo(body) {
  if (!body || typeof body !== 'object') return;
  const notesEl = $('infoNotes');
  const ramEl = $('infoRam');
  const keyEl = $('infoPubKey');
  if (notesEl && typeof body.notes === 'number') notesEl.textContent = body.notes.toLocaleString();
  if (ramEl && typeof body.ram_usage === 'string') ramEl.textContent = body.ram_usage;
  if (keyEl) keyEl.textContent = typeof body.pubkey === 'string' ? body.pubkey : '—';
}

async function pingApi(url) {
  const seq = ++apiCheckSeq;
  const base = apiBase(url);
  apiReachable = false;
  setDot('idle');
  setReach('idle', t('SETTINGS_CHECKING'));
  updateSendAvailability();

  try {
    const { response, body } = await fetchJson(apiEndpoint('/info', base), {
      headers: { Accept: 'application/json' },
      allowUnsigned: true,
    }, 4000);

    if (!response.ok) throw new Error('server error ' + response.status);
    if (seq !== apiCheckSeq || base !== apiBase()) return false;
    updateServerInfo(body);
    if (!apiPubKeyB64 && typeof body?.pubkey === 'string' && body.pubkey) {
      const pageApi = pageDefaultApi();
      if (pageApi && base === pageApi) setApiPubKey(body.pubkey);
    }
    apiReachable = true;
    setDot('ok');
    setReach('ok', t('SETTINGS_REACHABLE'));
    updateSendAvailability();
    return true;
  } catch {
    if (seq !== apiCheckSeq || base !== apiBase()) return false;
    apiReachable = false;
    setDot('err');
    setReach('err', t('SETTINGS_UNREACHABLE'));
    updateSendAvailability();
    return false;
  }
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

    const bits = body.pow.bits;
    if (!Number.isInteger(bits) || bits < 1 || bits > MAX_POW_BITS) {
      throw new Error('invalid PoW difficulty');
    }
    const challenge = body.pow.challenge;
    if (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge)) {
      throw new Error('invalid challenge format');
    }
    const expiresAt = body.pow.expires_at;
    const nowSec = Date.now() / 1000;
    if (!Number.isInteger(expiresAt) || expiresAt <= nowSec || expiresAt > nowSec + 86400) {
      throw new Error('invalid expires_at');
    }
    const serverMaxPlaintext = body?.limits?.max_plaintext_bytes;
    if (Number.isInteger(serverMaxPlaintext) && serverMaxPlaintext > 0 && serverMaxPlaintext <= 1024 * 1024) {
      maxPlaintextBytes = serverMaxPlaintext;
      updateCharMeter();
    }
    const entry = {
      challenge,
      bits,
      expiresAt,
    };
    if (powContextVersion !== version || apiBase() !== base) {
      throw new Error('PoW initialization was invalidated');
    }
    powCache[scope] = entry;
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

/* ── Char ring ── */
function updateCharMeter() {
  const n = plaintextByteLength($('noteInput').value);
  const pct = Math.min(1, n / maxPlaintextBytes);
  $('charTxt').textContent = n.toLocaleString() + ' / ' + maxPlaintextBytes.toLocaleString() + ' bytes';
  const fill = $('ringFill');
  fill.style.strokeDashoffset = (RING_PATH - (pct * RING_PATH)).toFixed(2);
  fill.classList.toggle('warn', pct > 0.9);
  updateSendAvailability();
}

function scheduleCharMeterUpdate() {
  requestAnimationFrame(updateCharMeter);
}

['input', 'change'].forEach(eventName => {
  $('noteInput').addEventListener(eventName, updateCharMeter);
});

['paste', 'cut', 'drop'].forEach(eventName => {
  $('noteInput').addEventListener(eventName, scheduleCharMeterUpdate);
});

document.querySelectorAll('input[name="ttl"]').forEach(r => {
  r.addEventListener('change', updateSendAvailability);
});

/* ── Stage indicator ── */
function paintComposeSeg(seg, state, tone) {
  seg.className = 'seg';
  if (state) seg.classList.add(state);
  if (tone) seg.classList.add(tone);
}

function renderComposeProgress(status) {
  const segs = [$('s1'), $('s2'), $('s3'), $('s4')];
  $('segs').classList.remove('pow-pulse');
  segs.forEach(seg => { seg.className = 'seg'; });

  if (status === 'challenge') {
    paintComposeSeg(segs[0], 'active', 'seg-violet');
  } else if (status === 'solving') {
    paintComposeSeg(segs[0], 'done', 'seg-violet');
    paintComposeSeg(segs[1], 'active', 'seg-blue');
    startPowPulse($('segs'));
  } else if (status === 'ready') {
    segs.forEach(seg => paintComposeSeg(seg, 'done', 'seg-green'));
  } else if (status === 'sending') {
    paintComposeSeg(segs[0], 'done', 'seg-violet');
    paintComposeSeg(segs[1], 'done', 'seg-blue');
    paintComposeSeg(segs[2], 'active', 'seg-blue');
  } else if (status === 'done') {
    segs.forEach(seg => paintComposeSeg(seg, 'done', 'seg-green'));
  }
}

function setComposeStatus(status, message = '') {
  const lbl = $('stageLbl');

  if (status === 'solving') {
    showPowSolvingMsg(lbl, 'status-lbl app-solving');
  } else if (status === 'error') {
    resetStatusEl(lbl, 'status-lbl', message, 'err');
  } else {
    const meta = {
      prepare: ['APP_PREPARE', 'app-prepare'],
      challenge: ['APP_GET_ANTIBOT', 'app-get-antibot'],
      ready: ['APP_READY', 'app-ready'],
      sending: ['APP_SENDING', 'app-sending'],
      done: ['APP_DONE', 'app-ready'],
    }[status];

    if (meta && !message) setTranslatedStatusEl(lbl, 'status-lbl', meta[0], meta[1]);
    else if (meta) resetStatusEl(lbl, 'status-lbl', message, meta[1]);
    else resetStatusEl(lbl, 'status-lbl', message);
  }

  renderComposeProgress(status);
  updateSendAvailability();
}

function setGatePowStatus(status, message = '') {
  const msg = $('gateMsg');

  if (status === 'solving') {
    showPowSolvingMsg(msg, 'status-msg app-solving');
  } else if (status === 'error') {
    resetStatusEl(msg, 'status-msg', message, 'err');
  } else if (status === 'ready') {
    if (message) resetStatusEl(msg, 'status-msg', message, 'app-ready');
    else setTranslatedStatusEl(msg, 'status-msg', 'APP_READY', 'app-ready');
  } else if (status === 'challenge') {
    if (message) resetStatusEl(msg, 'status-msg', message, 'app-get-antibot');
    else setTranslatedStatusEl(msg, 'status-msg', 'APP_GET_ANTIBOT', 'app-get-antibot');
  } else {
    resetStatusEl(msg, 'status-msg', message);
  }

  updateRevealAvailability();
}

/* ── Encoding / crypto ── */
function b64u(bytes) {
  const chunkSize = 0x8000;
  let raw = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    raw += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concatThree(a, b, c) {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
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

async function payloadHashCreate(ttl, blob) {
  const ttlBytes = new Uint8Array(8);
  const view = new DataView(ttlBytes.buffer);
  const high = Math.floor(ttl / 0x100000000);
  const low = ttl >>> 0;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);

  return sha256(concatBytes(ttlBytes, te.encode(blob)));
}

async function payloadHashView(nid) {
  return sha256(te.encode('view:' + nid));
}

function nonceFromCounter(counter) {
  const nonce = new Uint8Array(POW_NONCE_BYTES);
  const view = new DataView(nonce.buffer);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  view.setUint32(0, low, true);
  view.setUint32(4, high, true);
  return nonce;
}

async function encrypt(text) {
  const plaintext = te.encode(text);
  if (plaintext.byteLength > maxPlaintextBytes) {
    throw new Error('note exceeds ' + maxPlaintextBytes.toLocaleString() + ' bytes');
  }
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  );
  const blobBytes = concatBytes(iv, ciphertext);
  const viewToken = await sha256(keyBytes);

  return {
    blob: b64u(blobBytes),
    keyB64: b64u(keyBytes),
    viewTokenB64: b64u(viewToken),
  };
}

async function decrypt(blobB64, keyB64) {
  if (typeof blobB64 !== 'string' || blobB64.length > 32768) throw new Error('blob too large');
  if (typeof keyB64 !== 'string' || !KEY_RE.test(keyB64)) throw new Error('invalid key format');
  const blobBytes = fromb64u(blobB64, null, 'blob');
  if (blobBytes.length < AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES) throw new Error('invalid blob length');
  const iv = blobBytes.slice(0, AES_GCM_IV_BYTES);
  const ciphertext = blobBytes.slice(AES_GCM_IV_BYTES);
  const keyBytes = fromb64u(keyB64, AES_KEY_BYTES, 'key');
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return td.decode(plaintext);
}

async function viewTokenFromKey(keyB64) {
  return b64u(await sha256(fromb64u(keyB64, AES_KEY_BYTES, 'key')));
}

function setApiPubKey(b64) {
  apiPubKeyB64 = b64 || null;
  apiVerifyKey = null;
}

async function loadVerifyKey(b64) {
  if (!b64) { apiVerifyKey = null; return; }
  const keyBytes = fromb64u(b64, 32, 'Ed25519 public key');
  apiVerifyKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'Ed25519' }, false, ['verify']
  );
}

function solvePoWWithWorker(payload) {
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
      timer = setTimeout(() => finish(reject, new Error('PoW challenge expired')), timeoutMs);
    }

    worker.addEventListener('message', event => {
      const data = event.data || {};
      if (data.ok && data.nonce) {
        finish(resolve, data.nonce);
        return;
      }
      if (data.fatal) {
        finish(reject, new Error(data.message || 'PoW worker failed'));
      }
    });

    worker.addEventListener('error', event => {
      finish(reject, new Error(event.message || 'PoW worker failed'));
    });

    worker.postMessage(payload);
  });
}

async function solvePoWInMainThread(payload) {
  const challengeBytes = fromb64u(payload.challenge);
  const payloadHash = payload.mode === 'view'
    ? await payloadHashView(payload.nid)
    : await payloadHashCreate(payload.ttl, payload.blob);
  let counter = 0;

  while (true) {
    for (let i = 0; i < POW_CHUNK; i++) {
      const nonce = nonceFromCounter(counter++);
      const digest = await sha256(concatThree(challengeBytes, nonce, payloadHash));
      if (leadingZeroBits(digest, payload.bits)) return b64u(nonce);
    }
    if (payload.expiresAt && Date.now() >= payload.expiresAt * 1000) {
      throw new Error('PoW challenge expired');
    }
    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

async function solvePoW(payload) {
  if (location.protocol === 'file:') return solvePoWInMainThread(payload);

  try {
    return await solvePoWWithWorker(payload);
  } catch {
    return solvePoWInMainThread(payload);
  }
}

function buildHostedShareUrl(nid, keyB64) {
  if (!/^https?:$/.test(location.protocol)) {
    const remoteBase = apiBase();
    if (/^https:\/\//.test(remoteBase) && !isLoopbackHostname(new URL(remoteBase).hostname)) {
      const url = new URL(remoteBase);
      url.pathname = '/';
      url.search = '';
      url.searchParams.set('p', nid);
      url.hash = keyB64;
      return url.toString();
    }
    return buildLocalShareUrl(nid, keyB64);
  }
  const url = new URL(location.origin);
  url.pathname = '/';
  url.search = '';
  url.searchParams.set('p', nid);
  setApiQueryParam(url, apiUrl);
  url.hash = keyB64;
  return url.toString();
}

function buildLocalShareUrl(nid, keyB64) {
  const url = new URL(location.href);
  url.search = '';
  url.searchParams.set('p', nid);
  setApiQueryParam(url, apiUrl);
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
  const { urlStr: rawApiUrl, pubkeyB64: linkPubkey } = parseApiConfig(rawApiParam);
  if (!isSafeApiTransport(rawApiUrl)) throw new Error('link API must be HTTPS, or HTTP on localhost');
  const derivedApi = normalizeApiUrl(rawApiUrl);

  return {
    nid,
    key,
    api: derivedApi,
    pubkeyB64: linkPubkey,
  };
}

async function openSharedLink(raw) {
  const link = parseSharedLink(raw);
  const url = new URL(location.href);
  url.search = '';
  url.searchParams.set('p', link.nid);
  const fallbackApi = hostedDefaultApi(url);
  if (link.api && link.api !== fallbackApi) {
    url.searchParams.set('api', apiConfigString(link.api, link.pubkeyB64));
  }
  url.hash = link.key;

  history.pushState(null, '', url.toString());
  $('openLinkInp').value = '';
  $('openLinkMsg').textContent = '';
  $('openLinkMsg').className = 'status-msg open-link-msg';
  await route();
}

/* ── Send note ── */
$('sendBtn').addEventListener('click', async () => {
  const text = $('noteInput').value;
  if (!text.trim()) return;
  if (plaintextByteLength(text) > maxPlaintextBytes) {
    setComposeStatus('error', '⚠ note exceeds ' + maxPlaintextBytes.toLocaleString() + ' bytes');
    return;
  }

  const ttl = selectedTtl();
  const base = apiBase();
  const version = powContextVersion;
  const init = isPowFresh(powCache.create) ? powCache.create : null;
  if (!init) return;

  $('sendBtn').disabled = true;
  setComposeStatus('solving');

  try {
    const { blob, keyB64, viewTokenB64 } = await encrypt(text);
    const nonce = await solvePoW({
      challenge: init.challenge,
      bits: init.bits,
      expiresAt: init.expiresAt,
      mode: 'create',
      ttl,
      blob,
    });

    if (powContextVersion !== version || apiBase() !== base) {
      throw new Error('API changed while the request was being prepared');
    }

    setComposeStatus('sending');
    const { response, body } = await fetchJson(apiEndpoint('/api/v1/notes', base), {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        alg: 'aes-256-gcm',
        challenge: init.challenge,
        nonce,
        ttl,
        blob,
        view_token: viewTokenB64,
      }),
    });

    if (!response.ok || !body?.ok || !body?.nid) {
      throw responseError(response, body, 'failed to create note');
    }
    if (!NID_RE.test(body.nid)) throw new Error('invalid note id from server');

    setComposeStatus('done');
    curNid = body.nid;
    curKey = keyB64;

    const ttlLbl = ttl === 43200 ? '12h' : '24h';
    $('linkUrl').textContent = buildHostedShareUrl(body.nid, keyB64);
    $('ttlLbl').textContent = ttlLbl;
    $('metaTtl').textContent = '⏱ ' + ttlLbl;
    $('metaNid').textContent = 'id: ' + body.nid;
    if (location.protocol === 'file:') {
      const localUrl = buildLocalShareUrl(body.nid, keyB64);
      $('localLinkUrl').href = localUrl;
      $('localLinkUrl').textContent = localUrl;
      $('localShareCard').hidden = false;
    } else {
      $('localLinkUrl').href = '#';
      $('localLinkUrl').textContent = '';
      $('localShareCard').hidden = true;
    }
    $('qrWrap').classList.add('hidden');
    $('qrWrap').replaceChildren();
    $('qrBtn').textContent = 'show QR';
    powCache.create = null;
    clearTimeout(createRefreshTimer);
    createRefreshTimer = null;
    show('sLink');
  } catch (err) {
    powCache.create = null;
    clearTimeout(createRefreshTimer);
    createRefreshTimer = null;
    if (err?.code === 'no_pubkey') { showNoPubkeyModal(); return; }
    setComposeStatus('error', '⚠ ' + (err.message || 'error'));
    startComposeWarmup();
  }
});

/* ── Copy link ── */
$('copyBtn').addEventListener('click', async () => {
  const button = $('copyBtn');
  try {
    await navigator.clipboard.writeText($('linkUrl').textContent);
    button.textContent = 'copied!';
  } catch {
    button.textContent = 'failed';
  }
  setTimeout(() => { button.textContent = 'copy'; }, 1800);
});

/* ── QR ── */
$('qrBtn').addEventListener('click', () => {
  const wrap = $('qrWrap');
  const hidden = wrap.classList.contains('hidden');
  if (!hidden) {
    wrap.classList.add('hidden');
    $('qrBtn').textContent = 'show QR';
    return;
  }

  wrap.classList.remove('hidden');
  $('qrBtn').textContent = 'hide QR';
  if (typeof QRCode !== 'undefined') {
    try {
      const qr = QRCode({ msg: $('linkUrl').textContent, dim: 160, pad: 1, ecl: 'M' });
      wrap.replaceChildren(qr);
    } catch {
      wrap.textContent = 'failed to render QR';
    }
  } else {
    const msg = document.createElement('span');
    msg.className = 'mono muted small';
    msg.textContent = 'load qrcode.min.js to enable';
    wrap.replaceChildren(msg);
  }
});

/* ── New note ── */
function resetCompose() {
  curNid = '';
  curKey = '';
  clearPowCache();
  $('noteInput').value = '';
  $('noteOutput').value = '';
  updateCharMeter();
  setGatePowStatus('idle');
  $('burnTimer').textContent = '';
  $('burnedId').textContent = '';
  $('localLinkUrl').href = '#';
  $('localLinkUrl').textContent = '';
  $('localShareCard').hidden = true;
  $('openLinkInp').value = '';
  $('openLinkMsg').textContent = '';
  $('openLinkMsg').className = 'status-msg open-link-msg';
  history.replaceState(null, '', buildComposeUrl());
  show('sCompose');
  startComposeWarmup();
}
$('newBtn').addEventListener('click', resetCompose);
$('replyBtn').addEventListener('click', resetCompose);
$('sendOwnBtn').addEventListener('click', resetCompose);

/* ── Pre-solve view PoW when gate screen loads ── */
function startPresolveView() {
  if (!isGateVisible()) return;
  clearTimeout(viewRefreshTimer);
  presolvedViewNonce = null;
  updateRevealAvailability();
  setGatePowStatus('challenge');

  const version = powContextVersion;
  const state = { nid: curNid, version };
  presolveViewState = state;
  const pending = (async () => {
    try {
      const init = await getPowInit('view');
      if (presolveViewState !== state || powContextVersion !== version || !isGateVisible()) return null;
      scheduleViewPowRefresh(init.expiresAt);
      setGatePowStatus('solving');
      const nonce = await solvePoW({
        challenge: init.challenge,
        bits: init.bits,
        expiresAt: init.expiresAt,
        mode: 'view',
        nid: curNid,
      });
      if (presolveViewState !== state || powContextVersion !== version || !isGateVisible()) return null;
      presolvedViewNonce = nonce;
      setGatePowStatus('ready');
      return nonce;
    } catch (err) {
      if (presolveViewState === state && isGateVisible()) {
        if (err?.code === 'no_pubkey') { showNoPubkeyModal(); return null; }
        setGatePowStatus('error', '⚠ ' + (err.message || 'error'));
      }
      return null;
    } finally {
      if (presolveViewPromise === pending) presolveViewPromise = null;
      if (presolveViewState === state) presolveViewState = null;
    }
  })();

  presolveViewPromise = pending;
}

async function startComposeWarmup() {
  if (!isComposeVisible()) return;

  const seq = ++composeWarmupSeq;
  clearTimeout(createRefreshTimer);
  createRefreshTimer = null;
  powCache.create = null;
  powInitPromises.create = null;

  setComposeStatus('prepare');
  const ok = await pingApi(apiUrl);
  if (seq !== composeWarmupSeq || !isComposeVisible()) return;

  if (!ok) {
    setComposeStatus('error', '⚠ api unreachable');
    return;
  }

  try {
    setComposeStatus('challenge');
    const init = await getPowInit('create');
    if (seq !== composeWarmupSeq || !isComposeVisible()) return;
    scheduleCreatePowRefresh(init.expiresAt);
    setComposeStatus('ready');
  } catch (err) {
    if (seq !== composeWarmupSeq || !isComposeVisible()) return;
    if (err?.code === 'no_pubkey') { showNoPubkeyModal(); return; }
    setComposeStatus('error', '⚠ ' + (err.message || 'error'));
  }
}

/* ── Recipient: reveal ── */
$('revealBtn').addEventListener('click', async () => {
  const init = isPowFresh(powCache.view) ? powCache.view : null;
  const nonce = presolvedViewNonce;
  if (!init || !nonce) return;

  $('revealBtn').disabled = true;
  resetStatusEl($('gateMsg'), 'status-msg');

  try {
    const { response, body } = await fetchJson(
      apiEndpoint('/api/v1/notes/' + encodeURIComponent(curNid) + '/view'),
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          challenge: init.challenge,
          nonce,
          view_token: await viewTokenFromKey(curKey),
        }),
      }
    );

    if (response.status === 410) {
      $('burnedId').textContent = curNid ? 'id: ' + curNid + ' · already read by someone' : '';
      show('sBurned');
      return;
    }
    if (!response.ok || !body?.ok || !body?.blob) {
      throw responseError(response, body, 'failed to read note');
    }

    presolvedViewNonce = null;
    powCache.view = null;
    clearTimeout(viewRefreshTimer);
    viewRefreshTimer = null;
    const plain = await decrypt(body.blob, curKey);
    $('noteOutput').value = plain;
    $('burnTimer').textContent = 'destroyed on server';
    show('sRead');
  } catch (err) {
    presolvedViewNonce = null;
    powCache.view = null;
    clearTimeout(viewRefreshTimer);
    viewRefreshTimer = null;
    if (err?.code === 'no_pubkey') { showNoPubkeyModal(); return; }
    setGatePowStatus('error', '⚠ ' + (err.message || 'error'));
    if (isGateVisible()) startPresolveView();
  }
});

$('notYetBtn').addEventListener('click', () => history.back());

/* ── Copy text ── */
$('copyTxtBtn').addEventListener('click', async () => {
  const button = $('copyTxtBtn');
  try {
    await navigator.clipboard.writeText($('noteOutput').value);
    button.textContent = 'copied!';
  } catch {
    button.textContent = 'failed';
  }
  setTimeout(() => { button.textContent = 'copy text'; }, 1800);
});

$('burnBtn').addEventListener('click', () => {
  $('burnedId').textContent = curNid ? 'id: ' + curNid + ' · you closed it just now' : '';
  show('sBurned');
});

/* ── Open shared link locally ── */
$('openLinkBtn').addEventListener('click', async () => {
  try {
    await openSharedLink($('openLinkInp').value);
  } catch (err) {
    $('openLinkMsg').textContent = '⚠ ' + (err.message || 'error');
    $('openLinkMsg').className = 'status-msg open-link-msg err';
  }
});

$('openLinkInp').addEventListener('keydown', event => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  $('openLinkBtn').click();
});

/* ── Settings ── */
function openSettings() {
  $('apiInp').placeholder = location.origin;
  $('apiInp').value = apiUrl;
  $('oSettings').classList.remove('hidden');
  setTimeout(() => $('apiInp').focus(), 40);
}

function closeSettings() {
  $('oSettings').classList.add('hidden');
}

$('apiBadge').addEventListener('click', openSettings);
$('cogBtn').addEventListener('click', openSettings);
$('closeSettings').addEventListener('click', closeSettings);
$('cancelSettings').addEventListener('click', closeSettings);
$('oSettings').addEventListener('click', event => {
  if (event.target === $('oSettings')) closeSettings();
});

$('defaultBtn').addEventListener('click', () => {
  $('apiInp').value = DEFAULT_API;
});

$('saveSettings').addEventListener('click', async () => {
  const { urlStr: candidateUrl, pubkeyB64: candidatePubkey } = parseApiConfig(($('apiInp').value || '').trim() || DEFAULT_API);
  if (!isSafeApiTransport(candidateUrl)) {
    setReach('err', 'API must be HTTPS, or HTTP on localhost');
    return;
  }
  const nextApi = normalizeApiUrl(candidateUrl);
  closeSettings();

  if (isExternalApi(nextApi)) {
    if (candidatePubkey && nextApi !== confirmedApiUrl) {
      // Manual pubkey entered (url|pubkey) — trust directly without modal.
      setApiPubKey(candidatePubkey);
      saveTrustedApi(nextApi, candidatePubkey);
      confirmedApiUrl = nextApi;
    } else if (nextApi !== confirmedApiUrl) {
      const confirmed = await showApiConfirmModal(nextApi);
      if (!confirmed) return;
      confirmedApiUrl = nextApi;
      // apiPubKeyB64 already set inside showApiConfirmModal via setApiPubKey().
    }
  } else {
    setApiPubKey(DEFAULT_API_PUBKEY);
  }

  apiUrl = nextApi;
  storageSet(LS_KEY, apiUrl);
  clearPowCache();
  updateApiDisplay(apiUrl);
  if (isComposeVisible()) {
    startComposeWarmup();
  } else {
    pingApi(apiUrl);
    if (isGateVisible()) startPresolveView();
  }
});

/* ── Lang picker ── */
$('langBtn').addEventListener('click', event => {
  event.stopPropagation();
  $('langMenu').classList.toggle('hidden');
});

document.querySelectorAll('#langMenu [data-lang]').forEach(li => {
  li.addEventListener('click', () => {
    $('langMenu').classList.add('hidden');
    loadLang(li.dataset.lang);
  });
});

document.addEventListener('click', event => {
  if (!$('langWrap').contains(event.target)) {
    $('langMenu').classList.add('hidden');
  }
});

/* ── Runtime placeholder replacement ── */
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
    $('langMenu').classList.add('hidden');
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

function showExternalApiWarningModal(url) {
  return new Promise(resolve => {
    $('apiConfirmUrl').textContent = url;
    $('oApiConfirm').classList.remove('hidden');
    setTimeout(() => $('apiConfirmAccept').focus(), 40);

    function done(result) {
      $('oApiConfirm').classList.add('hidden');
      $('apiConfirmAccept').removeEventListener('click', onAccept);
      $('apiConfirmReject').removeEventListener('click', onReject);
      document.removeEventListener('keydown', onKey);
      $('oApiConfirm').removeEventListener('click', onBackdrop);
      resolve(result);
    }
    function onAccept() { done(true); }
    function onReject() { done(false); }
    function onKey(e) { if (e.key === 'Escape') done(false); }
    function onBackdrop(e) { if (e.target === $('oApiConfirm')) done(false); }

    $('apiConfirmAccept').addEventListener('click', onAccept);
    $('apiConfirmReject').addEventListener('click', onReject);
    document.addEventListener('keydown', onKey);
    $('oApiConfirm').addEventListener('click', onBackdrop);
  });
}

async function showApiConfirmModal(url) {
  const normalizedUrl = normalizeApiUrl(url);
  const storedPubkey = getTrustedPubkey(normalizedUrl);

  let prefetchedPubkey = null;

  // Auto-trust: already in trust store — verify pubkey against live /info.
  // User already accepted this API, so the request is justified without re-confirming.
  if (storedPubkey !== null) {
    prefetchedPubkey = await fetchApiPubkey(normalizedUrl);
    if (prefetchedPubkey !== null && storedPubkey === prefetchedPubkey) {
      if (prefetchedPubkey) setApiPubKey(prefetchedPubkey);
      return true;
    }
    // Pubkey changed or /info unreachable — fall through to show modals.
  }

  // Step 1: external API warning — shown BEFORE any /info request for new APIs.
  const proceed = await showExternalApiWarningModal(normalizedUrl);
  if (!proceed) return false;

  // Step 2: for new APIs, fetch now that user confirmed; for returning APIs with a
  // changed key, reuse the already-fetched result.
  const fetchedPubkey = prefetchedPubkey !== null ? prefetchedPubkey : await fetchApiPubkey(normalizedUrl);
  const keyChanged = storedPubkey !== null && fetchedPubkey !== null && storedPubkey !== fetchedPubkey;

  // Use textContent throughout — values are never parsed as HTML.
  $('apiTrustUrl').textContent = normalizedUrl;
  $('apiTrustPubkey').textContent = fetchedPubkey || '—';
  $('apiTrustKeyWarn').hidden = !keyChanged;
  $('oApiTrust').classList.remove('hidden');
  setTimeout(() => $('apiTrustAccept').focus(), 40);

  return new Promise(resolve => {
    function done(trusted) {
      $('oApiTrust').classList.add('hidden');
      $('apiTrustAccept').removeEventListener('click', onAccept);
      $('apiTrustReject').removeEventListener('click', onReject);
      document.removeEventListener('keydown', onKey);
      $('oApiTrust').removeEventListener('click', onBackdrop);
      if (trusted) {
        saveTrustedApi(normalizedUrl, fetchedPubkey);
        if (fetchedPubkey) setApiPubKey(fetchedPubkey);
      }
      resolve(trusted);
    }
    function onAccept() { done(true); }
    function onReject() { done(false); }
    function onKey(e) { if (e.key === 'Escape') done(false); }
    function onBackdrop(e) { if (e.target === $('oApiTrust')) done(false); }

    $('apiTrustAccept').addEventListener('click', onAccept);
    $('apiTrustReject').addEventListener('click', onReject);
    document.addEventListener('keydown', onKey);
    $('oApiTrust').addEventListener('click', onBackdrop);
  });
}

/* ── Router ── */
async function route() {
  const params = new URLSearchParams(location.search);
  const p = params.get('p');
  const key = location.hash.slice(1);
  const apiP = params.get('api');

  if (apiP) {
    const { urlStr: apiPUrl, pubkeyB64: apiPKey } = parseApiConfig(apiP);
    if (isSafeApiTransport(apiPUrl)) {
      apiUrl = normalizeApiUrl(apiPUrl);
      setApiPubKey(apiPKey);
      clearPowCache();
    }
  } else if (p && key) {
    const hostedApi = hostedDefaultApi();
    if (hostedApi && hostedApi !== apiUrl) {
      apiUrl = hostedApi;
      clearPowCache();
    }
  }

  updateApiDisplay(apiUrl);

  if (isExternalApi() && apiUrl !== confirmedApiUrl) {
    const confirmed = await showApiConfirmModal(apiUrl);
    if (!confirmed) {
      apiUrl = hostedDefaultApi();
      setApiPubKey(DEFAULT_API_PUBKEY);
      storageSet(LS_KEY, '');
      clearPowCache();
      updateApiDisplay(apiUrl);
      const cleanUrl = new URL(location.href);
      cleanUrl.searchParams.delete('api');
      history.replaceState(null, '', cleanUrl.toString());
    } else {
      confirmedApiUrl = apiUrl;
    }
  }

  if (p && key && NID_RE.test(p) && KEY_RE.test(key)) {
    curNid = p;
    curKey = key;
    show('sGate');
    pingApi(apiUrl);
    startPresolveView();
  } else {
    show('sCompose');
    startComposeWarmup();
  }
}

window.addEventListener('popstate', () => route());
route();
updateCharMeter();
loadLang(storageGet(LS_LANG_KEY, 'en'));
window.addEventListener('resize', fitSquigs);
requestAnimationFrame(fitSquigs);

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
            description: 'The text content to encrypt and send (max 4096 UTF-8 bytes by default).',
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
          const base = apiBase();
          const version = powContextVersion;
          const { blob, keyB64, viewTokenB64 } = await encrypt(text);
          const init = await getPowInit('create');
          const nonce = await solvePoW({ challenge: init.challenge, bits: init.bits, expiresAt: init.expiresAt, mode: 'create', ttl, blob });
          if (powContextVersion !== version || apiBase() !== base) return { error: 'API changed while the request was being prepared' };
          powCache.create = null;
          const { response, body } = await fetchJson(apiEndpoint('/api/v1/notes', base), {
            method: 'POST',
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify({ alg: 'aes-256-gcm', challenge: init.challenge, nonce, ttl, blob, view_token: viewTokenB64 }),
          });
          if (!response.ok || !body?.ok || !body?.nid || !NID_RE.test(body.nid)) {
            return { error: body?.error?.message || 'failed to create note' };
          }
          return {
            link: buildHostedShareUrl(body.nid, keyB64),
            note_id: body.nid,
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
