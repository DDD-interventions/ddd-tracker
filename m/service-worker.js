/* DDD Tracker — Mobile Service Worker
   Strategy:
   - App shell (HTML + icons + manifest): cache-first, falls back to network.
   - Everything else (Supabase REST/storage, jsdelivr CDN): network-only, let the app's offline queue handle persistence.
   - Bump CACHE_VERSION on every deploy where the shell changes. */

const CACHE_VERSION = 'ddd-m-v0.4.1';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  const isSameOrigin = url.origin === self.location.origin;
  const isInScope = isSameOrigin && url.pathname.startsWith('/ddd-tracker/m/');

  // App shell: cache-first
  if (isInScope) {
    event.respondWith(
      caches.match(req, { ignoreSearch: true }).then((cached) => {
        if (cached) return cached;
        return fetch(req).then((res) => {
          // Cache successful navigations + same-origin shell assets for next launch
          if (res && res.status === 200 && res.type === 'basic') {
            const clone = res.clone();
            caches.open(CACHE_VERSION).then((cache) => cache.put(req, clone));
          }
          return res;
        }).catch(() => caches.match('./index.html'));
      })
    );
    return;
  }

  // Everything else (Supabase, CDN): network-only. App handles offline via localStorage queue.
});
