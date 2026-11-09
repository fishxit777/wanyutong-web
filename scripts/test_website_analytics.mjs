// No HTTP is performed: all browser transports and documents are synthetic.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const source = readFileSync(new URL('assets/wanyutong-analytics.js', root), 'utf8');
const endpoint = 'https://one1stars-line-bot.onrender.com/track/event';
const line = 'https://line.me/R/ti/p/@969wpxno';

function harness(options = {}) {
  const beacons = [], fetches = [], listeners = new Map();
  let admin = options.admin ? '1' : null;
  const document = {
    readyState: options.readyState || 'complete', referrer: options.referrer || '',
    querySelectorAll() { return options.noindex ? [{ getAttribute() { return 'NOINDEX, follow'; } }] : []; },
    addEventListener(name, callback, settings) {
      const entries = listeners.get(name) || [];
      entries.push({ callback, once: Boolean(settings?.once) }); listeners.set(name, entries);
    }
  };
  const window = {
    location: new URL(options.url || 'https://wanyutong.tw/'),
    crypto: options.noCrypto ? undefined : (options.crypto || webcrypto),
    localStorage: { getItem() { if (options.storageThrows) throw new Error('storage disabled'); return admin; } },
    navigator: {
      sendBeacon(url, body) {
        beacons.push({ url, body });
        if (options.beaconThrows) throw new Error('beacon unavailable');
        return options.beaconReturns ?? true;
      }
    },
    fetch(url, settings) {
      fetches.push({ url, settings });
      if (options.fetchThrows) throw new Error('fetch unavailable');
      return options.fetchRejects ? Promise.reject(new Error('offline')) : Promise.resolve({ ok: true });
    }
  };
  if (options.noBeacon) delete window.navigator.sendBeacon;
  const context = vm.createContext({ window, document, URL, Blob, Uint8Array });
  const run = () => vm.runInContext(source, context);
  function emit(type, event = {}) {
    const entries = listeners.get(type) || [];
    for (const entry of [...entries]) {
      if (entry.once) entries.splice(entries.indexOf(entry), 1);
      entry.callback({ type, ...event });
    }
  }
  run();
  return {
    window, beacons, fetches, listeners, run, emit,
    admin(value) { admin = value ? '1' : null; },
    ready() { document.readyState = 'complete'; emit('DOMContentLoaded'); },
    click(href = line, options = {}) {
      const anchor = { getAttribute(name) { return name === 'href' ? href : null; } };
      const node = { closest() { return anchor; } };
      const target = options.textNode ? { parentElement: node } : node;
      emit(options.type || 'click', { target, isTrusted: true, button: 0, ...options });
    },
    async payloads() { return Promise.all(beacons.map(async ({ body }) => JSON.parse(await body.text()))); }
  };
}

test('every indexable public document loads one tracker with its own canonical page label', async () => {
  let tracked = 0;
  for (const name of readdirSync(root).filter(name => name.endsWith('.html'))) {
    const html = readFileSync(new URL(name, root), 'utf8');
    const trackable = /<head\b/i.test(html) && !/<meta\b[^>]*name=["']robots["'][^>]*content=["'][^"']*noindex/i.test(html);
    assert.equal((html.match(/src="assets\/wanyutong-analytics\.js\?v=20261110-v2"/g) || []).length, trackable ? 1 : 0, name);
    assert.ok(!html.includes('/track/pixel'), name);
    if (!trackable) continue;
    tracked++;
    const h = harness({ url: 'https://wanyutong.tw/' + name });
    assert.equal(h.beacons.length, 1, name);
    const [payload] = await h.payloads();
    assert.equal(payload.page, name.replace(/\.html$/, ''), name);
    assert.equal(payload.event_type, 'page_view');
    assert.match(payload.event_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  }
  assert.equal(tracked, 24);
});

test('root, index.html and allowed GitHub Pages root normalize to index', async () => {
  for (const url of ['https://wanyutong.tw/', 'https://www.wanyutong.tw/index.html', 'https://fishxit777.github.io/wanyutong-web/', 'https://fishxit777.github.io/wanyutong-web/index.html']) {
    const h = harness({ url });
    assert.equal((await h.payloads())[0].page, 'index');
  }
});

test('unapproved hosts, non-HTTPS, unknown, nested and noindex pages never transmit', () => {
  for (const url of ['file:///C:/index.html', 'http://localhost:8000/index.html', 'https://127.0.0.1/index.html', 'https://fake.wanyutong.tw/', 'https://example.com/', 'https://fishxit777.github.io/other/', 'https://wanyutong.tw/private.html', 'https://wanyutong.tw/private/index.html', 'https://wanyutong.tw/blog-image-ocr-checklist.html']) {
    const h = harness({ url }); h.click();
    assert.equal(h.beacons.length + h.fetches.length, 0, url);
  }
  const noindex = harness({ noindex: true }); noindex.click();
  assert.equal(noindex.beacons.length + noindex.fetches.length, 0);
});

test('double initialization, DOM readiness and bfcache return count one page view', () => {
  const h = harness({ readyState: 'loading' }); h.run();
  assert.equal(h.beacons.length, 0);
  h.ready(); h.ready(); h.emit('pageshow', { persisted: true }); h.run();
  assert.equal(h.beacons.length, 1);
  h.click(); assert.equal(h.beacons.length, 2);
  assert.equal(h.listeners.get('click').length, 1);
});

test('administrator exclusion applies on initial load and later click', () => {
  const h = harness({ admin: true }); h.click();
  assert.equal(h.beacons.length, 0);
  const later = harness(); later.admin(true); later.click();
  assert.equal(later.beacons.length, 1);
  assert.doesNotThrow(() => harness({ storageThrows: true }).click());
});

test('LINE mouse, keyboard and middle-button activations count only official outbound links', async () => {
  const h = harness({ url: 'https://wanyutong.tw/join.html' });
  h.click();
  h.click('https://line.me/ti/p/@969wpxno', { detail: 0 }); // Enter triggers native click.
  h.click(line, { type: 'auxclick', button: 1, textNode: true });
  h.click(line, { button: 1 }); // The preceding middle-button click is ignored.
  h.click(line, { type: 'auxclick', button: 2 });
  h.click('join.html');
  h.click('https://line.me/R/ti/p/@someoneelse');
  h.click('https://line.me.example.com/R/ti/p/@969wpxno');
  h.click('https://user:password@line.me/R/ti/p/@969wpxno');
  h.click(line, { defaultPrevented: true });
  h.click(line, { isTrusted: false });
  const events = await h.payloads();
  assert.deepEqual(events.map(item => item.event_type), ['page_view', 'line_click', 'line_click', 'line_click']);
  assert.equal(new Set(events.map(item => item.event_id)).size, events.length);
  assert.ok(events.every(item => item.page === 'join'));
});

test('events include only allowed fields; private paths, queries and credentials never enter payload', async () => {
  for (const [referrer, expected] of [
    ['https://source.example/private?token=synthetic#secret', 'https://source.example'],
    ['https://name:password@source.example/private', ''], ['file:///private', ''], ['not a URL', ''], ['', '']
  ]) {
    const h = harness({ url: 'https://wanyutong.tw/index.html?private=synthetic#secret', referrer });
    h.click(line + '?private=synthetic#secret');
    for (const payload of await h.payloads()) {
      assert.deepEqual(Object.keys(payload).sort(), ['event_id', 'event_type', 'page', 'referrer', 'version']);
      assert.equal(payload.referrer, expected);
      assert.equal(payload.version, 2);
      assert.ok(!JSON.stringify(payload).includes('synthetic'));
      assert.ok(!JSON.stringify(payload).includes('password'));
    }
    assert.ok(h.beacons.every(item => item.url === endpoint && item.body.type === 'text/plain;charset=utf-8'));
  }
});

test('rejected Beacon falls back once with exactly the same event ID and privacy protections', async () => {
  const h = harness({ beaconReturns: false });
  const [payload] = await h.payloads();
  assert.equal(h.beacons.length, 1);
  assert.equal(h.fetches.length, 1);
  assert.deepEqual(JSON.parse(h.fetches[0].settings.body), payload);
  assert.equal(h.fetches[0].url, endpoint);
  assert.equal(h.fetches[0].settings.keepalive, true);
  assert.equal(h.fetches[0].settings.credentials, 'omit');
  assert.equal(h.fetches[0].settings.referrerPolicy, 'no-referrer');
  assert.equal(h.fetches[0].settings.cache, 'no-store');
});

test('transport failures never prevent navigation and never retry indefinitely', async () => {
  for (const options of [
    { beaconThrows: true, fetchThrows: true }, { noBeacon: true, fetchRejects: true }, { beaconReturns: false, fetchRejects: true }
  ]) {
    const h = harness(options);
    let cancelled = false;
    assert.doesNotThrow(() => h.click(line, { preventDefault() { cancelled = true; } }));
    await Promise.resolve();
    assert.equal(cancelled, false);
    assert.equal(h.fetches.length, 2); // One page view and one click; no retry loop.
    assert.ok(h.beacons.length <= 2);
  }
});

test('UUID fallback is valid and a missing crypto implementation fails without blocking links', async () => {
  const fallback = harness({ crypto: { getRandomValues(bytes) { return webcrypto.getRandomValues(bytes); } } });
  assert.match((await fallback.payloads())[0].event_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  const absent = harness({ noCrypto: true });
  assert.doesNotThrow(() => absent.click());
  assert.equal(absent.beacons.length + absent.fetches.length, 0);
});

test('service worker versions the new script and never adds the tracking API to its cache', () => {
  const sw = readFileSync(new URL('sw.js', root), 'utf8');
  assert.match(sw, /20261110-content-sync-v3/);
  assert.ok(sw.includes("'./assets/wanyutong-analytics.js?v=20261110-v2'"));
  assert.ok(!sw.includes(endpoint));
  assert.match(sw, /request.method === 'GET'/);
});
