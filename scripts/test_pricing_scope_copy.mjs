import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const pricingSource = readFileSync(new URL('pricing.html', root), 'utf8');
const sharedSource = readFileSync(new URL('assets/wanyutong-app.js', root), 'utf8');
const pageRendererSource = pricingSource.slice(
  pricingSource.indexOf('function forcePricingLang(lang)'),
  pricingSource.indexOf('function forceCompareLang(lang)'),
);
const sharedRendererSource = sharedSource.slice(
  sharedSource.indexOf('function syncFinalPricing(activeLang)'),
  sharedSource.indexOf('function syncChromeText(lang)'),
);
const strip = (value) => value.replace(/<[^>]*>/g, '').trim();
const existingOrderZh = '本次說明不追溯縮減既有訂單的權益';
const existingOrderEn = 'This clarification does not retroactively reduce rights under existing orders';

function node(textContent = '') {
  return { textContent, style: {}, dataset: {}, remove() {} };
}

// Build the model from the page's real initial HTML, then run its real renderer
// and the deferred shared renderer. This catches last-writer copy regressions.
function harness(order) {
  const cards = [...pricingSource.matchAll(/<div class="price-card(?: featured| enterprise)?">([\s\S]*?<a[^>]*class="btn-plan"[\s\S]*?<\/a>)\s*<\/div>/g)].map(([html, body]) => {
    const pick = (className) => strip(body.match(new RegExp(`<div class="${className}">([\\s\\S]*?)<\\/div>`))?.[1] || '');
    const items = [...body.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((match) => node(strip(match[1])));
    const features = {
      children: items,
      appendChild(item) { this.children.push(item); },
      removeChild(item) { this.children.splice(this.children.indexOf(item), 1); },
      get lastElementChild() { return this.children.at(-1); },
      set innerHTML(value) { assert.equal(value, ''); this.children.length = 0; },
    };
    const parts = {
      '.price-plan': node(pick('price-plan')),
      '.price-amount': node(pick('price-amount')),
      '.price-period': node(pick('price-period')),
      '.price-features': features,
      '.btn-plan': node(''),
      '.price-badge': body.includes('price-badge') ? node(pick('price-badge')) : null,
    };
    parts['.btn-plan'].dataset.btn = html.includes('data-btn="join"') ? 'join' : 'contact';
    return {
      style: {},
      classList: { contains: (name) => name === 'enterprise' && html.includes(' enterprise') },
      querySelector(selector) { return selector === '.btn-plan[data-btn]' ? parts['.btn-plan'] : parts[selector] || null; },
      querySelectorAll(selector) { return selector === '.price-features li' ? features.children : []; },
      parts,
    };
  });
  assert.equal(cards.length, 5, 'fixture derives all five actual static cards');
  const initialScope = pricingSource.match(/<div id="premium-scope-note"[^>]*>([\s\S]*?)<\/div>/)[1];
  const scope = { innerHTML: initialScope, dataset: {} };
  const title = node(strip(pricingSource.match(/<h1[^>]*id="pricing-title"[^>]*>([\s\S]*?)<\/h1>/)[1]));
  const eyebrow = node('// Pricing');
  const lead = node('');
  const refund = node('');
  const tabs = [node('')];
  const section = {
    getAttribute(name) { return name === 'data-pricing-renderer' && order !== 'legacy' ? 'page' : null; },
    querySelector(selector) {
      if (order !== 'legacy') throw new Error('shared fallback must not query a page-owned pricing section');
      return { '.eyebrow': eyebrow, '#pricing-title, .section-title': title, '.lead': lead, '.pricing-tab': tabs[0], '.refund-note': refund }[selector] || null;
    },
    querySelectorAll(selector) { return order === 'legacy' && selector === '#tab-group .price-card, .pricing-grid .price-card' ? cards : []; },
  };
  const document = {
    getElementById(id) { return id === 'pricing' ? section : id === 'premium-scope-note' ? scope : null; },
    querySelector(selector) {
      if (selector === '#pricing-title') return title;
      if (selector === '#pricing .eyebrow') return eyebrow;
      if (selector === '#pricing .lead') return lead;
      if (selector === '.refund-note') return refund;
      return null;
    },
    querySelectorAll(selector) {
      if (selector === '#tab-group .price-card') return cards;
      if (selector === '.pricing-tab') return tabs;
      return [];
    },
    createElement() { return node(''); },
  };
  const global = { document };
  global.window = global;
  const context = vm.createContext(global);
  function registerPage() {
    vm.runInContext(pageRendererSource, context);
    vm.runInContext('window.wanyuPagePricingRenderer = forcePricingLang;', context);
  }
  if (order === 'page-first') registerPage();
  vm.runInContext(sharedRendererSource, context);
  if (order === 'shared-first') {
    context.syncFinalPricing('en');
    assert.equal(scope.innerHTML, initialScope, 'shared controller leaves static truth intact before registration');
    assert.equal(cards[4].parts['.price-features'].children.length, 7);
    registerPage();
  }
  return { context, cards, scope, title };
}

function assertFinal({ cards, scope, title }, lang) {
  const premium = cards[4];
  const features = premium.parts['.price-features'].children.map((item) => item.textContent);
  assert.equal(features.length, 7);
  assert.equal(premium.parts['.price-amount'].textContent, 'NT$2500');
  assert.ok(features.some((value) => value.includes('300')));
  assert.ok(features.some((value) => /客製需求|Confirm custom scope/.test(value)));
  assert.ok(features.every((value) => !/專屬客製化機器人|預計開發台語版、客語版|Dedicated custom bot|Planned Taiwanese and Hakka versions/.test(value)));
  const heading = strip(scope.innerHTML.match(/<h2[^>]*>([\s\S]*?)<\/h2>/)[1]);
  assert.equal(heading, lang === 'en' ? 'Premium: purchase scope and activation' : '尊爵版：購買範圍與開通流程');
  assert.equal(title.textContent, lang === 'en' ? 'Choose the Right Plan' : '選擇適合你的方案');
  assert.ok(scope.innerHTML.includes(lang === 'en' ? existingOrderEn : existingOrderZh));
  assert.deepEqual(cards.slice(1, 4).map((card) => card.parts['.price-amount'].textContent), ['NT$99', 'NT$499', 'NT$799']);
  assert.deepEqual(cards.slice(1, 4).map((card) => card.parts['.price-period'].textContent), lang === 'en' ? ['30 days', '180 days', '420 days'] : ['30 天', '180 天', '420 天']);
}

for (const order of ['page-first', 'shared-first']) {
  test(`page-owned pricing survives shared controller and language switches (${order})`, () => {
    const state = harness(order);
    for (const lang of ['zh', 'en', 'zh', 'en', 'zh']) {
      // The setLang wrapper runs shared synchronization after the page renderer.
      state.context.forcePricingLang(lang);
      state.context.syncFinalPricing(lang);
      assertFinal(state, lang);
      // load/pageshow can run the shared synchronization again.
      state.context.syncFinalPricing(lang);
      assertFinal(state, lang);
    }
  });
}

test('page uses a precise title selector and registers before deferred initialization', () => {
  assert.match(pricingSource, /<section id="pricing" data-pricing-renderer="page">/);
  assert.ok(pricingSource.includes("q('#pricing-title', 'price.h2')"));
  assert.ok(pricingSource.includes("text('#pricing-title', t.title)"));
  assert.ok(!pricingSource.includes("'#pricing h1, #pricing h2'"));
  const registration = pricingSource.indexOf('window.wanyuPagePricingRenderer = forcePricingLang;');
  const initialization = pricingSource.indexOf('// 初始化：讀取儲存的語言');
  assert.ok(registration > 0 && registration < initialization);
  assert.match(pricingSource, /<script src="assets\/wanyutong-app\.js\?v=content-truth-20261010" defer><\/script>/);
});

test('shared controller delegates only opt-in pages and retains non-opt-in fallback', () => {
  assert.match(sharedRendererSource, /getAttribute\('data-pricing-renderer'\) === 'page'/);
  assert.match(sharedRendererSource, /window\.wanyuPagePricingRenderer\(activeLang\);/);
  assert.ok(sharedRendererSource.indexOf('return;\n    }') < sharedRendererSource.indexOf('var zhPlans'));
  assert.ok(sharedRendererSource.includes("pricing.querySelector('#pricing-title, .section-title')"));
  assert.ok(!sharedRendererSource.includes("pricing.querySelector('h2')"));
});

test('shared fallback still renders standard plans on pages without ownership opt-in', () => {
  const state = harness('legacy');
  for (const lang of ['zh', 'en']) {
    state.context.syncFinalPricing(lang);
    assert.deepEqual(state.cards.slice(1, 4).map((card) => card.parts['.price-amount'].textContent), ['NT$99', 'NT$499', 'NT$799']);
    assert.deepEqual(state.cards.slice(1, 4).map((card) => card.parts['.price-period'].textContent), lang === 'en' ? ['30 days', '180 days', '420 days'] : ['30 天', '180 天', '420 天']);
    assert.equal(state.title.textContent, lang === 'en' ? 'Choose the Right Plan' : '選擇適合你的方案');
    assert.equal(state.cards[4].parts['.price-features'].children.length, 7);
    assert.ok(state.cards[4].parts['.price-features'].children.every((item) => !/專屬客製化機器人|預計開發台語版、客語版|Dedicated custom bot|Planned Taiwanese and Hakka versions/.test(item.textContent)));
  }
  assert.ok(!/專屬客製化機器人|預計開發台語版、客語版|Dedicated custom bot|Planned Taiwanese and Hakka versions/.test(sharedRendererSource));
});

test('empty feature placeholders do not render misleading blank bullets', () => {
  assert.match(pricingSource, /#pricing\s+\.price-features\s+li:empty\s*\{\s*display:\s*none;?\s*\}/);
});
