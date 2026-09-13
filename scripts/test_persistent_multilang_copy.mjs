import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');
const persistentCommandPages = [
  'join.html',
  'blog-language-settings.html',
  'blog-group-translation-checklist.html',
  'blog-line-group-translation.html',
];
const publicPages = [
  ...persistentCommandPages,
  'blog-line-bot-first-setup.html',
];
const faqPages = [
  'contact.html',
  'engine.html',
  'features.html',
  'index.html',
  'industries.html',
  'pricing.html',
  'start.html',
  'terms.html',
];
const currentGuidancePages = [...publicPages, ...faqPages];

test('public guidance uses the single persistent multilingual command', () => {
  for (const page of persistentCommandPages) {
    const html = read(page);
    assert.ok(html.includes('@多語'), page);
    assert.ok(html.includes('@多語 關閉'), page);
    assert.ok(!html.includes('@群組多語'), page);
  }
});

test('join guidance does not describe @多語 as a one-shot command', () => {
  const html = read('join.html');
  const terms = [
    '下一句同步翻成設定語言',
    'The next message is translated into every selected language',
    '次の文章を設定した全言語へ同時翻訳',
    '다음 메시지를 설정한 모든 언어로 번역',
    'then send one test message',
  ];
  for (const term of terms) assert.ok(!html.includes(term), term);
  assert.ok(html.includes('持續翻成設定語言'));
  assert.ok(html.includes('Persistent multilingual mode supports up to 8 languages at once'));
  assert.ok(html.includes('keeps translating later regular messages'));
});

test('FAQ language copy documents the validated bilingual mode switch', () => {
  for (const page of faqPages) {
    const html = read(page);
    assert.ok(html.includes('@多語 關閉'), `${page}: restore previous pair`);
    assert.ok(html.includes('@語言設定 繁體中文 英文'), `${page}: executable language command`);
    assert.ok(html.includes('有兩種方式回到雙語'), `${page}: two routes`);
    assert.ok(html.includes('設定新雙語並自動關閉持續多語'), `${page}: zh success`);
    assert.ok(html.includes('格式或語言無效時會保留原模式'), `${page}: zh validation failure`);
    assert.ok(html.includes('There are two ways to return to two-way translation'), `${page}: en two routes`);
    assert.ok(html.includes('restore the previous pair'), `${page}: en restore`);
    assert.ok(html.includes('automatically close persistent multilingual mode'), `${page}: en success`);
    assert.ok(html.includes('Invalid formats or languages leave the current mode unchanged'), `${page}: en validation failure`);
    assert.ok(!html.includes('@語言設定 Language A Language B'), `${page}: no English placeholder command`);
  }
  const terms = read('terms.html');
  assert.ok(terms.split('設定新雙語並自動關閉持續多語').length >= 3, 'terms.html: static and localized zh copy');
});

test('current public guidance rejects legacy commands and one-shot wording', () => {
  const bannedTerms = [
    '@群組多語',
    '下一句同步翻成設定語言',
    'The next message is translated into every selected language',
    '次の文章を設定した全言語へ同時翻訳',
    '다음 메시지를 설정한 모든 언어로 번역',
    'then send one test message',
    '個人聊天的 `@多語` 是單次',
    '@印尼',
    '@Indonesian',
  ];
  for (const page of currentGuidancePages) {
    const html = read(page);
    for (const term of bannedTerms) assert.ok(!html.includes(term), `${page}: ${term}`);
  }
});

test('setup and mode articles explain successful switching and validation failure', () => {
  const setup = read('blog-line-bot-first-setup.html');
  assert.ok(setup.includes('驗證成功後會切換為新雙語並自動關閉持續多語'));
  assert.ok(setup.includes('輸入無效時原模式不變'));

  for (const page of [
    'blog-language-settings.html',
    'blog-group-translation-checklist.html',
    'blog-line-group-translation.html',
  ]) {
    const html = read(page);
    assert.ok(html.includes('@語言設定'), page);
    assert.ok(html.includes('自動關閉持續多語'), page);
    assert.match(html, /(?:驗證失敗|格式或語言驗證失敗).*(?:原模式不變|保留原模式)|(?:原模式不變|保留原模式).*(?:驗證失敗|格式或語言驗證失敗)/, page);
  }
});

test('service worker uses a fresh cache for the public guidance release', () => {
  assert.match(read('sw.js'), /20260914-tutorial-video-refresh-v1/);
});
