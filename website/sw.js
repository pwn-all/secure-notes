const CACHE = 'secnote-v3';
const SHELL = ['/', '/app-config.js', '/app.js', '/styles.css', '/pow-worker.js', '/qrcode.min.js', '/logo.svg', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
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
    isApiSurface ||
    e.request.cache === 'no-store' ||
    e.request.cache === 'reload'
  ) {
    e.respondWith(fetch(e.request));
    return;
  }
  e.respondWith(
    fetch(e.request)
      .then(r => {
        if (r.ok) { const clone = r.clone(); caches.open(CACHE).then(c => c.put(e.request, clone)).catch(() => {}); }
        return r;
      })
      .catch(async () => {
        let r = await caches.match(e.request);
        if (!r && e.request.mode === 'navigate') r = await caches.match('/');
        return r ?? new Response('Offline', { status: 503 });
      })
  );
});
