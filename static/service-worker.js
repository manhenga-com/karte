const CACHE_NAME = 'karte-routeros-management-v19';
const STATIC_ASSETS = [
  '/',
  '/static/app.css',
  '/static/vendor/bootstrap.min.css',
  '/static/mikrotik-symbol.svg',
  '/static/mikrotik-logo.svg',
  '/static/manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)).catch(() => undefined)
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') {
    return;
  }
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
