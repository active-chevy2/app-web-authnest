const CACHE_NAME = 'auth-app-v1';
const ASSETS = [
	'/',
	'/index.html',
	'/styles.css',
	'/app.js',
	'/manifest.json'
];

self.addEventListener('install', (event) => {
	event.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			return cache.addAll(ASSETS).catch(() => {
				// Ignore cache failures during install
			});
		})
	);
	self.skipWaiting();
});

self.addEventListener('activate', (event) => {
	event.waitUntil(
		caches.keys().then((cacheNames) => {
			return Promise.all(
				cacheNames.map((cacheName) => {
					if (cacheName !== CACHE_NAME) {
						return caches.delete(cacheName);
					}
				})
			);
		})
	);
	self.clients.claim();
});

self.addEventListener('fetch', (event) => {
	// Skip non-GET requests
	if (event.request.method !== 'GET') return;

	// Skip API requests (let them go through network)
	if (event.request.url.includes('/api/')) {
		event.respondWith(
			fetch(event.request)
				.then((response) => response)
				.catch(() => new Response('Offline', { status: 503 }))
		);
		return;
	}

	// Cache-first strategy for assets
	event.respondWith(
		caches.match(event.request).then((response) => {
			if (response) return response;

			return fetch(event.request).then((response) => {
				// Don't cache non-successful responses
				if (!response || response.status !== 200 || response.type !== 'basic') {
					return response;
				}

				const responseToCache = response.clone();
				caches.open(CACHE_NAME).then((cache) => {
					cache.put(event.request, responseToCache);
				});

				return response;
			});
		}).catch(() => {
			return caches.match('/index.html');
		})
	);
});
