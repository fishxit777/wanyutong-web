import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const mediaRoot = process.env.WYT_MEDIA_DIR ? resolve(process.env.WYT_MEDIA_DIR) : fileURLToPath(new URL('assets/', root));
const read = (name) => readFileSync(new URL(name, root), 'utf8');
const readMedia = (name) => readFileSync(join(mediaRoot, name), 'utf8');

const media = {
  line: 'wanyutong-line-bot-tutorial-20261110',
  secretary: 'wanyutong-secretary-tutorial-20261110',
  activation: 'wanyutong-activation-flow-20261110',
};
const mediaRevision = '?v=content-sync-20261110';

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
      assert.ok(existsSync(join(mediaRoot, `${stem}${suffix}`)), path);
    }
    assert.match(readMedia(`${stem}.vtt`), /^WEBVTT(?:\r?\n|$)/, `${stem}.vtt`);
  }
});

test('service worker precaches lightweight media metadata but loads 1080p MP4 at runtime', () => {
  const worker = read('sw.js');
  const core = worker.match(/const CORE_ASSETS = \[([\s\S]*?)\n\];/)?.[1] || '';
  const runtime = worker.match(/const RUNTIME_MEDIA_ASSETS = \[([\s\S]*?)\n\];/)?.[1] || '';
  assert.match(worker, /20261110-content-sync-v3/);

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
  const captions = readMedia(`${media.line}.vtt`).replace(/\s/g, '');
  for (const term of [
    '第一個指定目標',
    '二十四小時快取',
    '不會重新翻譯',
    '不會再次扣額度',
    '原文或任一指定目標超出四語',
    '每則原始訊息計一則',
    '只在剩五、三、一、零則時提醒',
    'LINE平台目前不支援群組固定底部圖文選單',
    '小老鼠選單',
    '提醒不等於已證實翻錯',
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


test('all videos and diagrams use the new facts rather than obsolete benefit claims', () => {
  for (const stem of Object.values(media)) {
    const text = readMedia(`${stem}.vtt`).replace(/\s/g, '');
    for (const stale of ['四十九斜線五十','最近三百筆','已確認六人','觀看廣告','贊助內容']) {
      assert.ok(!text.includes(stale), `${stem}: ${stale}`);
    }
  }
  const secretary = readMedia(`${media.secretary}.vtt`).replace(/\s/g, '');
  assert.ok(secretary.includes('依回覆標示的實際整理筆數核對'));
  assert.ok(secretary.includes('誰已讀、誰已理解'));
  for (const name of ['line-bot-add','language-setting','group-confirmation','multilingual-reply','plan-and-activation','secretary-status']) {
    assert.ok(existsSync(join(mediaRoot, 'guides', `${name}.jpg`)), name);
  }
});
