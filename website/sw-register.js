// Relative URL: the worker and its scope follow the page, at the site root or under a path such as /notes/.
if ('serviceWorker' in navigator && /^https?:$/.test(location.protocol)) {
  navigator.serviceWorker.register('sw.js').catch(err => console.warn('Service worker not registered:', err && err.message));
}
