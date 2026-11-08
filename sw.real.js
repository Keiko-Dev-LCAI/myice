// MyICE Service Worker — HTML + API network-first; static assets cache-first
const VERSION = 'myice-v46.32';
const BACKEND_ORIGIN = 'https://web-production-a6add.up.railway.app';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  let url;
  try { url = new URL(req.url); } catch (_) {
    return;
  }

  // HTML navigations — network first, cache fallback
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then(res => {
        const clone = res.clone();
        caches.open(VERSION).then(c => c.put(req, clone));
        return res;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // Backend / medical API — network-first, never prefer stale cache.
  // On network failure, fall back to last cached copy if any (offline safety).
  // Do NOT cache.put successful API responses (avoids serving outdated meds/allergies).
  if (url.origin === BACKEND_ORIGIN) {
    e.respondWith(
      fetch(req, { cache: 'no-store' }).catch(() => caches.match(req))
    );
    return;
  }

  // Static assets — cache first
  e.respondWith(
    caches.match(req).then(cached => {
      return cached || fetch(req).then(res => {
        const clone = res.clone();
        caches.open(VERSION).then(c => c.put(req, clone));
        return res;
      });
    })
  );
});
