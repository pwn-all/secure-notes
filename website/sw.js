const CACHE = 'secnote-v2';
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
  if (new URL(e.request.url).pathname.startsWith('/api/')) {
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
