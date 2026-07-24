/**
 * DDD Interventions Tracker — Service Worker
 *
 * Strategy:
 *   - App shell (index.html, icons, manifest)  → cache-first, stale-while-revalidate
 *   - CDN scripts (jsdelivr, cloudflare cdn)  → cache-first, stale-while-revalidate
 *   - Supabase API + notify worker            → network-only (NEVER cached)
 *   - All other GETs                          → stale-while-revalidate
 *
 * Why this matters:
 *   Supabase calls MUST hit the network so data stays fresh. The app shell
 *   is cached so the app opens instantly and works offline (read-only;
 *   submissions queue via the existing localStorage queue when offline).
 *
 * Update strategy:
 *   Bump VERSION below when you change index.html or any cached asset.
 *   On next visit, the new SW installs, old caches are cleaned up, and
 *   the user sees the updated app shell on the next reload.
 */

const VERSION = 'v1.0.44';
const CACHE_NAME = `ddd-tracker-${VERSION}`;

// Precached on install — minimum needed for the app to open offline
const PRECACHE_URLS = [
  './',
  './index.html',
  './schools.json',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

// CDN hosts whose assets we cache opportunistically (libraries used by the app)
const CACHEABLE_CDN_HOSTS = [
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'unpkg.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com'
];

// Hosts we MUST NEVER cache — data must always be fresh
const NEVER_CACHE_HOST_PARTS = [
  'supabase.co',     // Supabase REST + storage
  'supabase.in',
  'workers.dev',     // Cloudflare Worker (ddd-notify)
  'resend.com'       // Email delivery
];

// ── INSTALL: precache the app shell ─────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
      .catch(err => console.warn('[SW] Precache failed:', err))
  );
});

// ── ACTIVATE: clean up old caches ───────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k.startsWith('ddd-tracker-') && k !== CACHE_NAME)
            .map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── FETCH: route requests through the right strategy ────────────────────────
self.addEventListener('fetch', event => {
  const req = event.request;

  // Only GET requests are cacheable; POSTs etc. always go to network
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch (e) { return; }

  // Skip non-http(s) requests (e.g. chrome-extension://, data:)
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return;

  // Never cache backend / data endpoints — these MUST be live
  const isNeverCache = NEVER_CACHE_HOST_PARTS.some(h => url.hostname.includes(h));
  if (isNeverCache) return;

  // Never cache version polling files — they must always be live for update detection
  if (url.pathname.endsWith('/version.txt') ||
      url.pathname.endsWith('/release-notes.json')) {
    return;
  }

  // Decide whether this is something we can cache
  const isSameOrigin = url.origin === self.location.origin;
  const isCacheableCdn = CACHEABLE_CDN_HOSTS.includes(url.hostname);
  const shouldCache = isSameOrigin || isCacheableCdn;

  if (!shouldCache) return;

  // Stale-while-revalidate
  event.respondWith(
    caches.match(req).then(cached => {
      const networkFetch = fetch(req)
        .then(response => {
          if (response && response.status === 200 && response.type !== 'opaqueredirect') {
            const clone = response.clone();
            caches.open(CACHE_NAME)
              .then(cache => cache.put(req, clone))
              .catch(() => { /* quota or other cache write error — ignore */ });
          }
          return response;
        })
        .catch(() => cached); // offline → return cached if we have it

      // Return cached immediately if available; otherwise wait for network
      return cached || networkFetch;
    })
  );
});

// ── MESSAGE: allow the page to trigger SW updates ───────────────────────────
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ── PUSH: show a notification when the server sends one ──────────────────────
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; }
  catch (e) { try { data = { body: event.data && event.data.text() }; } catch (_) { data = {}; } }
  const title = data.title || 'DDD Tracker';
  const options = {
    body: data.body || '',
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
    tag: data.tag || 'ddd-tracker',
    renotify: !!data.renotify,
    data: { url: data.url || self.registration.scope },
    requireInteraction: false
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// ── NOTIFICATIONCLICK: focus or open the app at the login screen ─────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || self.registration.scope;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if ('focus' in c) { try { c.navigate(target); } catch (e) {} return c.focus(); }
      }
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});
