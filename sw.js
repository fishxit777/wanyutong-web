const CACHE_PREFIX = 'wanyutong-pwa-';
const CACHE_NAME = CACHE_PREFIX + '20260914-public-status-copy-v2';
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
  './assets/wanyutong-line-bot-tutorial-20260914-poster.jpg',
  './assets/wanyutong-line-bot-tutorial-20260914.vtt?v=public-status-v2',
  './assets/wanyutong-secretary-tutorial-20260914-poster.jpg',
  './assets/wanyutong-secretary-tutorial-20260914.vtt?v=public-status-v2',
  './assets/wanyutong-activation-flow-20260914-poster.jpg',
  './assets/wanyutong-activation-flow-20260914.vtt?v=public-status-v2',
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

// 1080p videos are deliberately omitted from install-time precaching. They are
// allowlisted for runtime caching so a PWA install never depends on downloading
// all three large media files at once.
const RUNTIME_MEDIA_ASSETS = [
  './assets/wanyutong-line-bot-tutorial-20260914.mp4?v=public-status-v2',
  './assets/wanyutong-secretary-tutorial-20260914.mp4?v=public-status-v2',
  './assets/wanyutong-activation-flow-20260914.mp4?v=public-status-v2'
];

// This public-site worker must never become a cache for accounts, API data,
// payment URLs, query-string credentials, or another application's responses.
const PUBLIC_ASSET_URLS = new Set(
  CORE_ASSETS.concat(RUNTIME_MEDIA_ASSETS).map((path) => new URL(path, self.location.href).href)
);

function isPublicAssetRequest(request) {
  return request.method === 'GET' &&
    PUBLIC_ASSET_URLS.has(request.url) &&
    !request.headers.has('authorization') &&
    !request.headers.has('range') &&
    !/(?:^|,)\s*no-store\b/i.test(request.headers.get('cache-control') || '') &&
    request.cache !== 'no-store';
}

function isPublicAssetResponse(response, request) {
  if (!response || response.status !== 200 || response.redirected) return false;
  if (response.type !== 'basic' && response.type !== 'default') return false;
  if (response.url && response.url !== request.url) return false;
  // Cache Storage does not enforce HTTP Cache-Control on our behalf.
  const cacheControl = response.headers.get('cache-control') || '';
  const vary = response.headers.get('vary') || '';
  return !/(?:^|,)\s*(?:private|no-store)\b/i.test(cacheControl) &&
    !/(?:^|,)\s*(?:\*|cookie|authorization)\s*(?:,|$)/i.test(vary);
}

async function fetchPublicAsset(request, event) {
  const response = await fetch(request);
  const copy = isPublicAssetResponse(response, request) ? response.clone() : null;
  // A full disk or disabled storage must not turn a successful network fetch
  // into an apparent site outage. Keep writes alive until they have settled.
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => (
    copy ? cache.put(request, copy) : cache.delete(request)
  )).catch(() => {}));
  return response;
}

async function matchPublicAsset(request) {
  try {
    const cache = await caches.open(CACHE_NAME);
    const response = await cache.match(request);
    return isPublicAssetResponse(response, request) ? response : undefined;
  } catch (error) {
    return undefined;
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => Promise.all(CORE_ASSETS.map(async (path) => {
        const url = new URL(path, self.location.href).href;
        const request = new Request(url, { credentials: 'omit', cache: 'reload', redirect: 'error' });
        const response = await fetch(request);
        if (!isPublicAssetResponse(response, request)) throw new Error('Public asset is not cacheable');
        await cache.put(request, response);
      })))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (!isPublicAssetRequest(request)) return;

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
      fetchPublicAsset(request, event).catch(async () => {
        const cached = await matchPublicAsset(request);
        if (cached) return cached;
        if (request.mode === 'navigate') {
          const home = await matchPublicAsset(new Request(new URL('./index.html', self.location.href)));
          if (home) return home;
        }
        return Response.error();
      })
    );
    return;
  }

  event.respondWith(
    matchPublicAsset(request).then((cached) => {
      if (cached) return cached;
      return fetchPublicAsset(request, event);
    })
  );
});
