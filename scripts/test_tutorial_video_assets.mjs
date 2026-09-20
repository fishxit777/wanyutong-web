import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');

const media = {
  line: 'wanyutong-line-bot-tutorial-20260920',
  secretary: 'wanyutong-secretary-tutorial-20260914',
  activation: 'wanyutong-activation-flow-20260920',
};
const mediaRevision = '?v=quota-picker-v1';

const placements = [
  ['features.html', media.line],
  ['features.html', media.secretary],
  ['join.html', media.line],
  ['join.html', media.activation],
  ['pricing.html', media.activation],
];

test('current pages embed the versioned MP4, poster, and optional caption track', () => {
  for (const [page, stem] of placements) {
    const html = read(page);
    assert.ok(html.includes(`poster="assets/${stem}-poster.jpg"`), `${page}: ${stem} poster`);
    assert.ok(html.includes(`<source src="assets/${stem}.mp4${mediaRevision}" type="video/mp4">`), `${page}: ${stem} source`);
    assert.ok(
      html.includes(`<track kind="captions" src="assets/${stem}.vtt${mediaRevision}" srclang="zh-Hant" label="繁體中文字幕">`),
      `${page}: ${stem} captions`,
    );
  }
});

test('burned-in captions are not doubled by a default browser caption track', () => {
  for (const page of ['features.html', 'join.html', 'pricing.html']) {
    const html = read(page);
    assert.doesNotMatch(html, /<track[^>]+\bdefault(?:\s|>)/i, page);
  }
});

test('all current tutorial media files exist and WebVTT files are valid', () => {
  for (const stem of Object.values(media)) {
    for (const suffix of ['.mp4', '-poster.jpg', '.vtt']) {
      const path = `assets/${stem}${suffix}`;
      assert.ok(existsSync(new URL(path, root)), path);
    }
    assert.match(read(`assets/${stem}.vtt`), /^WEBVTT(?:\r?\n|$)/, `${stem}.vtt`);
  }
});

test('service worker precaches lightweight media metadata but loads 1080p MP4 at runtime', () => {
  const worker = read('sw.js');
  const core = worker.match(/const CORE_ASSETS = \[([\s\S]*?)\n\];/)?.[1] || '';
  const runtime = worker.match(/const RUNTIME_MEDIA_ASSETS = \[([\s\S]*?)\n\];/)?.[1] || '';
  assert.match(worker, /20260920-quota-picker-v1/);

  for (const stem of Object.values(media)) {
    const mp4 = `./assets/${stem}.mp4${mediaRevision}`;
    assert.ok(!core.includes(mp4), `${mp4} must not block PWA installation`);
    assert.ok(runtime.includes(mp4), `${mp4} must remain runtime allowlisted`);
    assert.ok(core.includes(`./assets/${stem}-poster.jpg`), `${stem} poster`);
    assert.ok(core.includes(`./assets/${stem}.vtt${mediaRevision}`), `${stem} VTT`);
  }
  assert.match(worker, /CORE_ASSETS\.concat\(RUNTIME_MEDIA_ASSETS\)/);
  assert.match(worker, /Promise\.all\(CORE_ASSETS\.map/);
});

test('active pages and worker do not reference superseded tutorial assets', () => {
  for (const file of ['features.html', 'join.html', 'pricing.html', 'sw.js']) {
    const source = read(file);
    assert.ok(!source.includes('20260819'), `${file}: dated legacy asset`);
    assert.ok(!source.includes('wanyutong-line-bot-tutorial-20260914'), `${file}: legacy LINE Bot tutorial`);
    assert.ok(!source.includes('wanyutong-activation-flow-20260914'), `${file}: legacy activation tutorial`);
    assert.doesNotMatch(
      source,
      /assets\/wanyutong-(?:line-bot-tutorial|secretary-tutorial|activation-flow)\.(?:mp4|jpg|vtt)/,
      `${file}: unversioned legacy asset`,
    );
  }
});

test('superseded tutorial binaries have been removed from the release tree', () => {
  const legacy = [
    'assets/wanyutong-activation-flow-20260819-poster.jpg',
    'assets/wanyutong-activation-flow-20260819.mp4',
    'assets/wanyutong-activation-flow-poster.jpg',
    'assets/wanyutong-activation-flow.mp4',
    'assets/wanyutong-line-bot-tutorial-20260819-poster.jpg',
    'assets/wanyutong-line-bot-tutorial-20260819.mp4',
    'assets/wanyutong-line-bot-tutorial.mp4',
    'assets/wanyutong-line-bot-tutorial-20260914-poster.jpg',
    'assets/wanyutong-line-bot-tutorial-20260914.mp4',
    'assets/wanyutong-line-bot-tutorial-20260914.vtt',
    'assets/wanyutong-secretary-tutorial-20260819-poster.jpg',
    'assets/wanyutong-secretary-tutorial-20260819.mp4',
    'assets/wanyutong-secretary-tutorial-poster.jpg',
    'assets/wanyutong-secretary-tutorial.mp4',
    'assets/wanyutong-activation-flow-20260914-poster.jpg',
    'assets/wanyutong-activation-flow-20260914.mp4',
    'assets/wanyutong-activation-flow-20260914.vtt',
  ];
  for (const path of legacy) {
    assert.ok(!existsSync(new URL(path, root)), `${path} should stay deleted`);
  }
});

test('current LINE Bot captions explain exact quota and cached language buttons', () => {
  const captions = read(`assets/${media.line}.vtt`);
  for (const term of [
    '第一個指定目標',
    '二十四小時快取',
    '不會重新翻譯',
    '不會再次扣額度',
    '原文或任一指定目標超出四語',
    '每則原始訊息計一則',
    '四十九斜線五十',
  ]) assert.ok(captions.includes(term), term);
});

test('language coverage copy distinguishes total support from simultaneous selection', () => {
  for (const page of ['features.html', 'pricing.html']) {
    const html = read(page);
    assert.ok(html.includes('總支援 36 種'), `${page}: total language support`);
    assert.ok(html.includes('持續多語最多同時 8 種'), `${page}: simultaneous limit`);
    assert.ok(html.includes('36 common languages in total'), `${page}: English total support`);
    assert.ok(html.includes('Persistent multilingual mode supports up to 8 at once'), `${page}: English simultaneous limit`);
  }
});
