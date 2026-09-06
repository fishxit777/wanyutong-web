// Local-only fake-DOM tests: no real Google requests, clicks, or impressions.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const source = readFileSync(new URL('assets/wanyutong-ads.js', root), 'utf8');
const configSource = readFileSync(new URL('assets/wanyutong-ads-config.js', root), 'utf8');
const article = 'blog-line-group-translation.html';
const syntheticPublisher = 'ca-pub-' + '0'.repeat(16);
const googleLoader = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';

function node(tag = 'div', initial = {}) {
  const attrs = { ...initial };
  return {
    tagName: tag.toUpperCase(), hidden: true, style: {}, children: [],
    setAttribute(name, value) { attrs[name] = String(value); },
    getAttribute(name) { return name === 'src' ? this.src || attrs[name] || null : attrs[name] ?? null; },
    removeAttribute(name) { delete attrs[name]; },
    appendChild(child) { this.children.push(child); return child; }
  };
}

function harness(options = {}) {
  const config = {
    enabled: true, approvalConfirmed: true, consentReady: true,
    mode: 'content_ads_only', publisherId: syntheticPublisher,
    enabledPaths: [article], excludedPaths: [], slots: { articleInline: '1234567890' },
    ...options.config
  };
  const slots = options.noSlots ? [] : [node('div', { 'data-wyt-ad': options.slotKey || 'articleInline' })];
  const scripts = (options.existingScripts || []).map((src) => node('script', { src }));
  const appendedScripts = [];
  const listeners = {};
  const document = {
    readyState: options.readyState || 'loading',
    head: { appendChild(script) { scripts.push(script); appendedScripts.push(script); } },
    createElement: node,
    querySelector(selector) {
      if (selector.includes('noindex')) return options.noindex ? node('meta') : null;
      return null;
    },
    querySelectorAll(selector) {
      if (selector === '[data-wyt-ad]') return slots;
      if (selector === 'script[src]') return scripts;
      if (selector === 'meta[name="robots"]') return options.noindex ? [node('meta', { content: typeof options.noindex === 'string' ? options.noindex : 'noindex, follow' })] : [];
      return [];
    },
    addEventListener(name, callback) { (listeners[name] ||= []).push(callback); }
  };
  let pushCount = 0;
  const window = {
    WANYUTONG_ADS: config,
    location: new URL(options.url || 'https://wanyutong.tw/' + article),
    adsbygoogle: { push() { pushCount += 1; if (options.pushThrows) throw new Error('synthetic-provider-error'); } }
  };
  const context = vm.createContext({ window, document, URL, WeakSet, Object, Array, String });
  vm.runInContext(source, context);
  return {
    window, config, slots, scripts, appendedScripts,
    get pushCount() { return pushCount; },
    ready() { (listeners.DOMContentLoaded || []).forEach((callback) => callback()); },
    reloadController() { vm.runInContext(source, context); },
    addSlot() { const slot = node('div', { 'data-wyt-ad': 'articleInline' }); slots.push(slot); return slot; }
  };
}

function assertNoAds(h) {
  h.ready();
  h.window.wytAds.refresh();
  assert.equal(h.appendedScripts.length, 0);
  assert.equal(h.pushCount, 0);
  assert.ok(h.slots.every((slot) => slot.hidden && slot.children.length === 0));
}

test('deployed configuration leaves all three release gates closed', () => {
  const context = { window: {} };
  vm.runInNewContext(configSource, context);
  const cfg = context.window.WANYUTONG_ADS;
  for (const name of ['enabled', 'approvalConfirmed', 'consentReady']) assert.equal(cfg[name], false, name);
  assert.equal(cfg.mode, 'content_ads_only');
  assert.equal(cfg.enabledPaths.length, 9);
  assert.ok(cfg.enabledPaths.every((path) => /^blog-[a-z-]+\.html$/.test(path)));
  assert.ok(Object.values(cfg.slots).every((value) => value === ''));
});

for (const flag of ['enabled', 'approvalConfirmed', 'consentReady']) {
  for (const value of [false, undefined, 'true']) {
    test(`closed or nonboolean ${flag} gate blocks loading (${String(value)})`, () => {
      assertNoAds(harness({ config: { [flag]: value } }));
    });
  }
}

for (const path of [
  '/', '/index.html', '/blog.html', '/pricing.html', '/join.html', '/start.html', '/privacy.html',
  '/admin', '/payment', '/free-unlock', '/blog-new-unreviewed.html',
  '/blog-factory-line-translation.html', '/blog-caregiver-line-translation.html',
  '/blog-construction-line-translation.html', '/blog-foreign-worker-safety-law.html',
  '/blog-restaurant-foreign-worker-translation.html',
  '/folder/' + article, '/' + article + '-extra', '/' + article + '/',
  '/BLOG-line-group-translation.html', '/blog%2Dline-group-translation.html',
  '/' + article + '?source=synthetic', '/' + article + '#synthetic'
]) {
  test(`unreviewed or noncanonical route denied: ${path}`, () => {
    // Config alone is not allowed to enlarge the reviewed-route list.
    assertNoAds(harness({ url: 'https://wanyutong.tw' + path, config: { enabledPaths: [path.slice(1), article] } }));
  });
}

for (const origin of ['http://wanyutong.tw', 'https://example.invalid', 'https://wanyutong.tw.example.invalid', 'http://localhost:8877']) {
  test(`nonproduction origin denied: ${origin}`, () => assertNoAds(harness({ url: origin + '/' + article })));
}

test('empty allowlist denies by default', () => assertNoAds(harness({ config: { enabledPaths: [] } })));
test('legacy substring allowlist is not accepted', () => assertNoAds(harness({ config: { enabledPaths: ['blog-'] } })));
test('excluded exact route wins over the allowlist', () => assertNoAds(harness({ config: { excludedPaths: [article] } })));
test('excluded slash-prefixed route wins over the allowlist', () => assertNoAds(harness({ config: { excludedPaths: ['/' + article] } })));
test('noindex page cannot load ads even if configured', () => assertNoAds(harness({ noindex: true })));
test('uppercase NOINDEX directive is respected', () => assertNoAds(harness({ noindex: 'NOINDEX, FOLLOW' })));
test('unrecognized ad mode fails closed', () => assertNoAds(harness({ config: { mode: 'all_pages' } })));
test('malformed publisher cannot load ads', () => assertNoAds(harness({ config: { publisherId: 'invalid-synthetic-id' } })));
test('no DOM slots means no third-party script', () => assertNoAds(harness({ noSlots: true })));

for (const value of ['', ' ', 'abc', '<synthetic>', '123;456', '1'.repeat(21), null]) {
  test(`invalid slot does not trigger loader (length ${String(value).length})`, () => {
    assertNoAds(harness({ config: { slots: { articleInline: value } } }));
  });
}
test('prototype slot keys are not accepted', () => assertNoAds(harness({ slotKey: 'toString' })));

test('each of the nine reviewed articles can pass only with explicitly opened gates and a valid slot', () => {
  const cfgContext = { window: {} };
  vm.runInNewContext(configSource, cfgContext);
  for (const path of cfgContext.window.WANYUTONG_ADS.enabledPaths) {
    const h = harness({ url: 'https://wanyutong.tw/' + path, config: { enabledPaths: [path] } });
    h.ready();
    assert.equal(h.pushCount, 1, path);
    assert.equal(h.appendedScripts.length, 1, path);
  }
});

test('valid article loads once and mounts each element once across reentry', () => {
  const h = harness();
  h.ready();
  h.ready();
  h.window.wytAds.refresh();
  h.reloadController();
  h.window.wytAds.refresh();
  assert.equal(h.appendedScripts.length, 1);
  assert.equal(h.pushCount, 1);
  assert.equal(h.slots[0].children.length, 1);
  assert.equal(h.slots[0].hidden, false);
  assert.equal(h.slots[0].getAttribute('data-wyt-ad-state'), 'mounted');
});

test('a later new slot is mounted once without a second script', () => {
  const h = harness();
  h.ready();
  const second = h.addSlot();
  h.window.wytAds.refresh();
  h.window.wytAds.refresh();
  assert.equal(h.appendedScripts.length, 1);
  assert.equal(h.pushCount, 2);
  assert.equal(second.children.length, 1);
});

test('already-ready document initializes once', () => {
  const h = harness({ readyState: 'complete' });
  h.window.wytAds.refresh();
  assert.equal(h.appendedScripts.length, 1);
  assert.equal(h.pushCount, 1);
});

test('preexisting matching loader is reused without another script', () => {
  const h = harness({ existingScripts: [googleLoader + '?client=' + syntheticPublisher] });
  h.ready();
  h.window.wytAds.refresh();
  assert.equal(h.appendedScripts.length, 0);
  assert.equal(h.pushCount, 1);
});

test('preexisting mismatched loader fails closed', () => {
  assertNoAds(harness({ existingScripts: [googleLoader + '?client=invalid-synthetic-id'] }));
});

test('provider push error is hidden and not blindly retried', () => {
  const h = harness({ pushThrows: true });
  h.ready();
  h.window.wytAds.refresh();
  assert.equal(h.pushCount, 1);
  assert.equal(h.slots[0].hidden, true);
  assert.equal(h.slots[0].getAttribute('data-wyt-ad-state'), 'provider-error');
});

test('status omits publisher identity and URL query values', () => {
  const h = harness({ url: 'https://wanyutong.tw/' + article + '?synthetic=private' });
  const status = h.window.wytAds.status();
  assert.equal(status.enabled, false);
  assert.equal('publisherId' in status, false);
  assert.equal('publisherId' in h.window.wytAds, false);
  assert.equal(JSON.stringify(status).includes('private'), false);
});

test('static HTML never bypasses the guarded loader with a direct ad script', () => {
  const pages = readdirSync(root).filter((name) => name.endsWith('.html'));
  const violations = pages.filter((name) => {
    const html = readFileSync(new URL(name, root), 'utf8');
    return /<script\b[^>]*src\s*=\s*["'][^"']*pagead2\.googlesyndication\.com\/pagead\/js\/adsbygoogle\.js/i.test(html);
  });
  assert.equal(violations.length, 0, 'Direct ad-loader bypass remains on: ' + violations.join(', '));
});

test('ownership verification matches ads.txt without revealing its value', () => {
  const cfgContext = { window: {} };
  vm.runInNewContext(configSource, cfgContext);
  const publisher = cfgContext.window.WANYUTONG_ADS.publisherId;
  const adsTxt = readFileSync(new URL('ads.txt', root), 'utf8');
  const verified = /^ca-pub-\d{16}$/.test(publisher) && adsTxt.includes('google.com, ' + publisher.slice(3) + ', DIRECT,');
  assert.equal(verified, true, 'Existing publisher and ads.txt must remain consistent');
  const home = readFileSync(new URL('index.html', root), 'utf8');
  const meta = home.match(/<meta\s+name=["']google-adsense-account["']\s+content=["']([^"']+)["']/i);
  assert.equal(Boolean(meta && meta[1] === publisher), true, 'Homepage must preserve matching official meta verification');
});
