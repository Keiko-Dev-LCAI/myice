/* Maintenance gate. Do not cache or serve the app shell. */
self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil((async function () {
    var keys = await caches.keys();
    await Promise.all(keys.map(function (key) { return caches.delete(key); }));
    var windows = await self.clients.matchAll({ type: 'window' });
    await Promise.all(windows.map(function (client) { return client.navigate(client.url); }));
    await self.registration.unregister();
  })());
});

self.addEventListener('fetch', function (event) {
  if (event.request.mode !== 'navigate') return;
  event.respondWith(fetch(event.request, { cache: 'no-store' }));
});
