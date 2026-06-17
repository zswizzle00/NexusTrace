// Service Worker for NexusTrace
//
// Strategy:
//   - Navigations (HTML pages): network-first, fall back to cache when offline.
//     This guarantees users always get fresh pages after a deploy - never a stale shell.
//   - Same-origin static assets (CSS/JS/fonts/images): stale-while-revalidate.
//     Fast paint from cache, with a background refresh so the next load is current.
//   - Everything else (cross-origin, non-GET): passed straight to the network.
//
// Bump CACHE_NAME whenever the precache list or caching logic changes; the activate
// handler purges any cache whose name doesn't match.
const CACHE_NAME = 'nexustrace-v12';
const PRECACHE_URLS = [
    '/static/css/tailwind.css',
    '/static/css/styles.css',
    '/static/css/app.css',
    '/static/js/mobile.js',
    '/static/fonts/inter-latin-400-normal.woff2',
    '/static/fonts/inter-latin-600-normal.woff2',
    '/static/fonts/inter-latin-700-normal.woff2',
    '/static/favicon_io/favicon.ico',
    '/static/favicon_io/apple-touch-icon.png',
];

self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(names => Promise.all(
                names.filter(name => name !== CACHE_NAME).map(name => caches.delete(name))
            ))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', event => {
    const { request } = event;

    // Only handle GET; let the browser deal with POST/PUT/etc.
    if (request.method !== 'GET') return;

    const url = new URL(request.url);

    // Network-first for page navigations so deploys are picked up immediately.
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then(response => {
                    const copy = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
                    return response;
                })
                .catch(() => caches.match(request))
        );
        return;
    }

    // Stale-while-revalidate for same-origin static assets only.
    if (url.origin === self.location.origin && url.pathname.startsWith('/static/')) {
        event.respondWith(
            caches.match(request).then(cached => {
                const network = fetch(request)
                    .then(response => {
                        caches.open(CACHE_NAME).then(cache => cache.put(request, response.clone()));
                        return response;
                    })
                    .catch(() => cached);
                return cached || network;
            })
        );
    }
    // Anything else: default browser handling (no respondWith).
});
