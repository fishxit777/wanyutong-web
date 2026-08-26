const CACHE_NAME = 'wanyutong-pwa-20260827-digital-card-v1';
const CORE_ASSETS = [
  './',
  './index.html',
  './about.html',
  './blog.html',
  './features.html',
  './pricing.html',
  './start.html',
  './compare.html',
  './engine.html',
  './industries.html',
  './faq.html',
  './privacy.html',
  './terms.html',
  './contact.html',
  './card.html',
  './join.html',
  './blog-caregiver-line-translation.html',
  './blog-construction-line-translation.html',
  './blog-factory-line-translation.html',
  './blog-foreign-worker-communication.html',
  './blog-foreign-worker-safety-law.html',
  './blog-image-ocr-translation.html',
  './blog-line-group-translation.html',
  './blog-restaurant-foreign-worker-translation.html',
  './blog-line-bot-first-setup.html',
  './blog-language-settings.html',
  './blog-free-paid-plans.html',
  './blog-group-translation-checklist.html',
  './blog-image-ocr-checklist.html',
  './blog-translation-quality-checklist.html',
  './manifest.webmanifest',
  './ads.txt',
  './assets/wanyutong-app.js',
  './assets/wanyutong-ads-config.js',
  './assets/wanyutong-ads.js',
  './assets/wanyutong-readable.css',
  './assets/wanyutong-guide.css',
  './assets/wanyutong-card.css',
  './assets/wanyutong-card.js',
  './assets/wanyutong-line-qr.png',
  './assets/wanyutong-line-bot-tutorial-20260819.mp4',
  './assets/wanyutong-line-bot-tutorial-20260819-poster.jpg',
  './assets/wanyutong-secretary-tutorial-20260819.mp4',
  './assets/wanyutong-secretary-tutorial-20260819-poster.jpg',
  './assets/wanyutong-activation-flow-20260819.mp4',
  './assets/wanyutong-activation-flow-20260819-poster.jpg',
  './assets/icons/wanyutong-icon-180.png',
  './assets/icons/wanyutong-icon-192.png',
  './assets/icons/wanyutong-icon-512.png',
  './assets/blog/caregiver-line-translation.jpg',
  './assets/blog/construction-line-translation.svg',
  './assets/blog/factory-line-translation.jpg',
  './assets/blog/foreign-worker-communication.jpg',
  './assets/blog/foreign-worker-safety-law.jpg',
  './assets/blog/image-ocr-translation.jpg',
  './assets/blog/line-group-translation.jpg',
  './assets/blog/restaurant-foreign-worker.jpg',
  './assets/guides/line-bot-add.jpg',
  './assets/guides/language-setting.jpg',
  './assets/guides/multilingual-reply.jpg',
  './assets/guides/group-confirmation.jpg',
  './assets/guides/plan-and-activation.jpg',
  './assets/guides/secretary-status.jpg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  const accept = request.headers.get('accept') || '';
  const destination = request.destination || '';
  const shouldRefreshFirst =
    request.mode === 'navigate' ||
    accept.indexOf('text/html') !== -1 ||
    destination === 'script' ||
    destination === 'style' ||
    destination === 'worker';

  if (shouldRefreshFirst) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match('./index.html')))
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      });
    })
  );
});
