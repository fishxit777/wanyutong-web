// Dependency-free, local-only regression tests. No real requests or user data.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const workerSource = readFileSync(new URL('sw.js', root), 'utf8');
const origin = 'https://site.example';
const cachePrefix = workerSource.match(/const CACHE_PREFIX = ['"](wanyutong-pwa-)['"];/)?.[1];
const cacheVersion = workerSource.match(/const CACHE_NAME = CACHE_PREFIX \+ ['"]([^'"]+)['"];/)?.[1];
assert.ok(cachePrefix && cacheVersion, 'Worker must declare a versioned WanyuTong public cache');
const currentCache = cachePrefix + cacheVersion;
const keyFor = (request) => typeof request === 'string' ? new URL(request, origin).href : request.url;

function makeHarness() {
  const listeners = {};
  const stores = new Map();
  const calls = [];
  const deleted = [];
  let network = async () => new Response('public', { headers: { 'cache-control': 'public, max-age=600' } });
  let storageFails = false;
  const caches = {
    async open(name) {
      if (storageFails) throw new Error('storage unavailable');
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async put(request, response) { store.set(keyFor(request), response); },
        async match(request) { return store.get(keyFor(request))?.clone(); },
        async delete(request) { return store.delete(keyFor(request)); }
      };
    },
    async keys() { return [...stores.keys()]; },
    async delete(name) { deleted.push(name); return stores.delete(name); }
  };
  const sandbox = {
    URL, Request, Response, Set, Promise, caches,
    self: {
      location: new URL('/sw.js', origin),
      addEventListener(name, listener) { listeners[name] = listener; },
      async skipWaiting() {},
      clients: { async claim() {} }
    },
    fetch: async (request) => { calls.push(request); return network(request); }
  };
  vm.runInNewContext(workerSource, sandbox, { filename: 'sw.js' });
  return {
    calls, stores, deleted, caches,
    setNetwork(fn) { network = fn; },
    failStorage() { storageFails = true; },
    async lifecycle(name) {
      const work = [];
      listeners[name]({ waitUntil(promise) { work.push(promise); } });
      await Promise.all(work);
    },
    async dispatch(path, options = {}) {
      const { destination = '', navigate = false, ...init } = options;
      const request = new Request(new URL(path, origin), init);
      Object.defineProperty(request, 'destination', { value: destination });
      if (navigate) Object.defineProperty(request, 'mode', { value: 'navigate' });
      let result;
      const work = [];
      listeners.fetch({ request, respondWith(promise) { result = promise; }, waitUntil(promise) { work.push(promise); } });
      if (result === undefined) return { intercepted: false };
      const response = await result;
      await Promise.all(work);
      return { intercepted: true, response };
    }
  };
}

test('PWA install caches only existing public files without cookies', async () => {
  const h = makeHarness();
  await h.lifecycle('install');
  assert.ok(h.calls.length > 40);
  const versionedCaptions = new Set([
    '/assets/wanyutong-line-bot-tutorial-20260920.vtt',
    '/assets/wanyutong-secretary-tutorial-20260914.vtt',
    '/assets/wanyutong-activation-flow-20260920.vtt',
  ]);
  for (const request of h.calls) {
    assert.equal(request.credentials, 'omit');
    assert.equal(request.redirect, 'error');
    const url = new URL(request.url);
    if (url.search) {
      assert.ok(versionedCaptions.has(url.pathname), `unexpected versioned asset: ${url.pathname}`);
      assert.equal(url.search, '?v=quota-picker-v1');
    }
    assert.ok(existsSync(fileURLToPath(new URL('.' + url.pathname, root))));
  }
});

test('activation removes old WanyuTong caches and preserves other applications', async () => {
  const h = makeHarness();
  for (const name of ['wanyutong-pwa-old', currentCache, 'other-application']) await h.caches.open(name);
  await h.lifecycle('activate');
  assert.deepEqual(h.deleted, ['wanyutong-pwa-old']);
  assert.ok(h.stores.has('other-application'));
  assert.ok(h.stores.has(currentCache));
});

for (const path of ['/api/profile', '/admin', '/auth/callback', '/payment/return', '/private/export.csv', '/index.html?token=synthetic', '/assets/wanyutong-card.js?secret=synthetic', 'https://external.example/index.html']) {
  test('worker bypasses non-public URL ' + path.split('?')[0], async () => {
    const h = makeHarness();
    assert.equal((await h.dispatch(path, { navigate: true })).intercepted, false);
    assert.equal(h.calls.length, 0);
    assert.equal(h.stores.size, 0);
  });
}

for (const options of [{ method: 'POST' }, { headers: { authorization: 'Bearer synthetic-test-only' } }, { headers: { range: 'bytes=0-100' } }, { headers: { 'cache-control': 'no-store' } }, { cache: 'no-store' }]) {
  test('worker bypasses sensitive or partial request ' + JSON.stringify(Object.keys(options)), async () => {
    const h = makeHarness();
    assert.equal((await h.dispatch('/index.html', options)).intercepted, false);
    assert.equal(h.calls.length, 0);
  });
}

for (const headers of [{ 'cache-control': 'private, max-age=600' }, { 'cache-control': 'public, no-store' }, { vary: '*' }, { vary: 'Accept-Encoding, Cookie' }, { vary: 'Authorization' }]) {
  test('private response is returned but never persisted: ' + JSON.stringify(headers), async () => {
    const h = makeHarness();
    const cache = await h.caches.open(currentCache);
    await cache.put(origin + '/index.html', new Response('stale'));
    h.setNetwork(async () => new Response('private fixture', { headers }));
    const result = await h.dispatch('/index.html', { navigate: true });
    assert.equal(await result.response.text(), 'private fixture');
    assert.equal(h.stores.get(currentCache).has(origin + '/index.html'), false);
  });
}

test('redirected, opaque and error responses never enter the public cache', async () => {
  for (const kind of ['redirect', 'opaque', 'error']) {
    const h = makeHarness();
    h.setNetwork(async () => {
      const response = new Response('fixture', { status: kind === 'error' ? 500 : 200 });
      if (kind === 'redirect') Object.defineProperty(response, 'redirected', { value: true });
      if (kind === 'opaque') Object.defineProperty(response, 'type', { value: 'opaque' });
      return response;
    });
    await h.dispatch('/index.html', { navigate: true });
    assert.equal(h.stores.get(currentCache).size, 0);
  }
});

test('normal public navigation refreshes online and remains readable offline', async () => {
  const h = makeHarness();
  assert.equal(await (await h.dispatch('/index.html', { navigate: true })).response.text(), 'public');
  h.setNetwork(async () => { throw new Error('offline'); });
  assert.equal(await (await h.dispatch('/index.html', { navigate: true })).response.text(), 'public');
  assert.equal(await (await h.dispatch('/about.html', { navigate: true })).response.text(), 'public');
});

test('failed script fetch never falls back to an HTML document', async () => {
  const h = makeHarness();
  await h.dispatch('/index.html', { navigate: true });
  h.setNetwork(async () => { throw new Error('offline'); });
  const result = await h.dispatch('/assets/wanyutong-app.js', { destination: 'script' });
  assert.equal(result.response.type, 'error');
});

test('storage failure does not hide a successful online response', async () => {
  const h = makeHarness();
  h.failStorage();
  assert.equal(await (await h.dispatch('/index.html', { navigate: true })).response.text(), 'public');
});

test('installation rejects private responses', async () => {
  const h = makeHarness();
  h.setNetwork(async () => new Response('fixture', { headers: { 'cache-control': 'private' } }));
  await assert.rejects(h.lifecycle('install'), /not cacheable/);
  assert.equal(h.stores.get(currentCache).size, 0);
});

test('all inline and standalone JavaScript parses without executing page code', () => {
  for (const name of readdirSync(root).filter((name) => name.endsWith('.html'))) {
    const html = readFileSync(new URL(name, root), 'utf8');
    for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      if (/\bsrc\s*=|application\/ld\+json/i.test(match[1])) continue;
      new vm.Script(match[2], { filename: name });
    }
  }
  for (const name of readdirSync(new URL('assets/', root)).filter((name) => name.endsWith('.js'))) {
    new vm.Script(readFileSync(new URL('assets/' + name, root), 'utf8'), { filename: name });
  }
});

test('tracking pixels transmit only HTTP(S) origins and suppress the Referer header', () => {
  let pages = 0;
  for (const name of readdirSync(root).filter((name) => name.endsWith('.html'))) {
    const html = readFileSync(new URL(name, root), 'utf8');
    const block = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((match) => match[1]).find((source) => source.includes('/track/pixel'));
    if (!block) continue;
    pages += 1;
    for (const [referrer, expected] of [['https://source.example/private/synthetic?token=synthetic#fragment', 'https://source.example'], ['', ''], ['invalid', ''], ['file:///synthetic-private-path', '']]) {
      const images = [];
      vm.runInNewContext(block, {
        URL, encodeURIComponent,
        document: { referrer },
        location: new URL(origin),
        localStorage: { getItem() { return null; } },
        Image: function () { images.push(this); }
      });
      assert.equal(images.length, 1, name);
      assert.equal(new URL(images[0].src).searchParams.get('r'), expected, name);
      assert.equal(images[0].referrerPolicy, 'no-referrer', name);
      assert.ok(!images[0].src.includes('synthetic'), name);
    }
  }
  assert.equal(pages, 9);
});
