import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');
const publicPages = [
  'join.html',
  'blog-language-settings.html',
  'blog-group-translation-checklist.html',
  'blog-line-group-translation.html',
];

test('public guidance uses the single persistent multilingual command', () => {
  for (const page of publicPages) {
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
  assert.ok(html.includes('Later regular messages keep translating'));
});

test('service worker uses a fresh cache for the public guidance release', () => {
  assert.match(read('sw.js'), /20260911-persistent-multilang-v1/);
});
