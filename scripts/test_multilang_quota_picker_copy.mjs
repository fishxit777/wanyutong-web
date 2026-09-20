import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');

const quotaPages = [
  'assets/wanyutong-app.js',
  'index.html',
  'features.html',
  'pricing.html',
  'join.html',
  'faq.html',
  'terms.html',
  'compare.html',
  'contact.html',
  'engine.html',
  'industries.html',
  'start.html',
  'blog-free-paid-plans.html',
  'blog-language-settings.html',
  'blog-line-bot-first-setup.html',
  'blog-line-group-translation.html',
];

test('active quota copy explains source-or-target one-message accounting', () => {
  const combined = quotaPages.map(read).join('\n');
  for (const phrase of [
    '原文或任一指定目標',
    '每則原始訊息計 1 則',
    '每日 50 則',
    '中文含繁體與簡體',
    '今日剩餘 49/50 則',
    '群組由全群組共用',
  ]) {
    assert.ok(combined.includes(phrase), phrase);
  }

  for (const page of quotaPages) {
    const source = read(page);
    assert.ok(source.includes('原文或任一指定目標'), `${page}: source-or-target rule`);
    assert.ok(source.includes('每則原始訊息計 1 則'), `${page}: one-original-message rule`);
  }

  for (const stale of [
    '中文、英文、日文、韓文無限免費；其他語言每日50則',
    '中文、英文、日文、韓文翻譯不限次數；其他支援語言每日 50 則',
    'The free plan has unlimited Chinese, English, Japanese, and Korean use; other languages include 50 messages per day.',
  ]) {
    for (const page of quotaPages) {
      assert.ok(!read(page).includes(stale), `${page}: ${stale}`);
    }
  }
});

test('English pricing copy applies the same detected-source-or-target rule', () => {
  for (const page of ['assets/wanyutong-app.js', 'contact.html', 'engine.html', 'features.html', 'index.html', 'industries.html', 'join.html', 'pricing.html', 'start.html', 'terms.html', 'faq.html', 'blog-line-bot-first-setup.html']) {
    const html = read(page);
    assert.match(html, /detected source or any configured target/i, page);
    assert.match(html, /one original message uses one of 50 daily credits/i, page);
  }
});

test('public multilingual guidance documents the copyable primary and cached language buttons', () => {
  const pages = [
    'about.html',
    'features.html',
    'join.html',
    'blog-language-settings.html',
    'blog-line-group-translation.html',
    'blog-group-translation-checklist.html',
  ];
  const combined = pages.map(read).join('\n');
  for (const phrase of [
    '第一個指定目標',
    '可複製主語言',
    '其他語言以按鈕逐一查看',
    '24 小時',
    '不會重新翻譯或再扣額度',
    'LINE 訊息無法收回或摺疊',
  ]) {
    assert.ok(combined.includes(phrase), phrase);
  }
});

test('help and onboarding copy describes one primary reply plus language buttons', () => {
  for (const page of ['join.html', 'blog-line-bot-first-setup.html', 'start.html']) {
    const html = read(page);
    assert.ok(html.includes('繁中主內容'), page);
    assert.ok(html.includes('英文、日文、韓文按鈕'), page);
    assert.ok(!html.includes('依序回覆繁體中文、英文、日文與韓文'), page);
    assert.ok(!html.includes('return Traditional Chinese, English, Japanese, and Korean messages in order'), page);
  }
});
