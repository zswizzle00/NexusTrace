// Service Worker for NexusTrace
const CACHE_NAME = 'nexustrace-v1.0.0';
const urlsToCache = [
    '/',
    '/static/css/styles.css',
    '/static/js/mobile.js',
    '/static/js/main.js',
    '/static/favicon_io/favicon.ico',
    '/static/favicon_io/apple-touch-icon.png'
];

// Install event
self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Fetch event
self.addEventListener('fetch', event => {
    // No caching, just pass-through
});

// Activate event
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
    event.waitUntil(self.clients.claim());
}); 