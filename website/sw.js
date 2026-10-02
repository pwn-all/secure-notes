const CACHE = 'secnote-v4';
const SHELL = ['/', '/app-config.js', '/app.js', '/styles.css', '/pow-worker.js', '/qrcode.min.js', '/logo.svg', '/manifest.json'];
const STATIC_PATHS = new Set([...SHELL, '/index.html',
  ...['en', 'ru', 'ua', 'de', 'es', 'fr', 'pt', 'ar', 'bn', 'cn', 'hi', 'ur'].map(lang => '/langs/' + lang + '.json')]);

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
  const isApiSurface =
    url.pathname.startsWith('/api/') ||
    url.pathname === '/info' ||
    url.pathname === '/.well-known/api-catalog';

  if (
    e.request.method !== 'GET' ||
    url.origin !== self.location.origin ||
    !STATIC_PATHS.has(url.pathname) ||
    isApiSurface ||
    e.request.cache === 'no-store' ||
    e.request.cache === 'reload'
  ) {
    e.respondWith(fetch(e.request));
    return;
  }
  // Cache only the public shell. Note IDs, pins and arbitrary query strings must
  // never become persistent CacheStorage keys or cached response URLs.
  const cacheUrl = new URL(url.pathname === '/index.html' ? '/' : url.pathname, self.location.origin).toString();
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
        if (!r && e.request.mode === 'navigate') r = await cache.match('/');
        return r ?? new Response('Offline', { status: 503 });
      })
  );
});
