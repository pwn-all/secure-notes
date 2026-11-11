// Every path is relative to this script, so the offline shell works at a site root (/) and under a
// path such as /notes/ alike. The registration scope is the directory this script is served from.
const CACHE = 'secnote-v6';
const BASE = new URL('./', self.location.href).href;
const at = path => new URL(path, BASE).href;
const SHELL = ['./', 'app-config.js', 'app.js', 'styles.css', 'pow-worker.js', 'argon2.js', 'qrcode.min.js', 'logo.svg', 'manifest.json'].map(at);
const INDEX = at('index.html');
const STATIC_URLS = new Set([...SHELL, INDEX,
  ...['en', 'ru', 'ua', 'de', 'es', 'fr', 'pt', 'ar', 'bn', 'cn', 'hi', 'ur'].map(lang => at('langs/' + lang + '.json'))]);

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k.startsWith('secnote-') && k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // The API always sits at the root of its origin.
  const isApiSurface =
    url.pathname.startsWith('/api/') ||
    url.pathname === '/info' ||
    url.pathname === '/.well-known/api-catalog';
  const assetUrl = url.origin + url.pathname;

  if (
    e.request.method !== 'GET' ||
    url.origin !== self.location.origin ||
    !STATIC_URLS.has(assetUrl) ||
    isApiSurface ||
    e.request.cache === 'no-store' ||
    e.request.cache === 'reload'
  ) {
    e.respondWith(fetch(e.request));
    return;
  }
  // Cache only the public shell. Note IDs, pins and arbitrary query strings must
  // never become persistent CacheStorage keys or cached response URLs.
  const cacheUrl = assetUrl === INDEX ? BASE : assetUrl;
  e.respondWith(
    fetch(cacheUrl, { credentials: 'omit', redirect: 'error' })
      .then(r => {
        if (r.ok) {
          const clone = r.clone();
          e.waitUntil(caches.open(CACHE).then(c => c.put(cacheUrl, clone)).catch(() => {}));
        }
        return r;
      })
      .catch(async () => {
        const cache = await caches.open(CACHE);
        let r = await cache.match(cacheUrl);
        if (!r && e.request.mode === 'navigate') r = await cache.match(BASE);
        return r ?? new Response('Offline', { status: 503 });
      })
  );
});
