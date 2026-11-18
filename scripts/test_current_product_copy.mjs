import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');
const pages = readdirSync(root).filter((name) => name.endsWith('.html'));
const publicPages = pages.filter((name) => !/content=["']noindex/i.test(read(name)));

test('every inline script remains parseable and structured data is valid JSON', () => {
  for (const name of pages) {
    for (const [index, match] of [...read(name).matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].entries()) {
      if (/\bsrc\s*=/i.test(match[1]) || !match[2].trim()) continue;
      if (/application\/ld\+json/i.test(match[1])) JSON.parse(match[2]);
      else if (!/\btype\s*=\s*["'](?:text\/template|application\/json)["']/i.test(match[1])) {
        new vm.Script(match[2], { filename: `${name}:inline-${index}` });
      }
    }
  }
});

test('each structured FAQ answer matches its visible question by title, not array position', () => {
  const source = read('faq.html');
  const entities = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  const plain = (value) => value.replace(/<[^>]*>/g, ' ')
    .replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (_, key) => {
      if (key[0] === '#') return String.fromCodePoint(key[1].toLowerCase() === 'x'
        ? parseInt(key.slice(2), 16) : parseInt(key.slice(1), 10));
      return entities[key.toLowerCase()];
    }).replace(/\s+/g, ' ').trim();
  const answers = new Map([...source.matchAll(/<div[^>]*id="fa(\d+)"[^>]*>([\s\S]*?)<\/div>/g)]
    .map((match) => [match[1], plain(match[2])]));
  const byTitle = new Map([...source.matchAll(/<span[^>]*id="fq(\d+)"[^>]*>([\s\S]*?)<\/span>/g)]
    .map((match) => [plain(match[2]), answers.get(match[1])]));
  const schema = [...source.matchAll(/<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)]
    .map((match) => JSON.parse(match[1])).find((value) => value['@type'] === 'FAQPage');
  assert.ok(schema && schema.mainEntity.length > 0);
  // The schema deliberately selects only some FAQs; its positions cannot be
  // used as visible fa1/fa2/... identifiers.
  assert.ok(schema.mainEntity.length < byTitle.size);
  for (const item of schema.mainEntity) {
    const title = plain(item.name);
    assert.ok(byTitle.has(title), `Structured FAQ has no visible question: ${title}`);
    assert.equal(plain(item.acceptedAnswer.text), byTitle.get(title), `Answer mismatch: ${title}`);
  }
  assert.equal(schema.dateModified, '2026-11-18');
});

test('retired acknowledgement and exaggerated translation promises cannot return in static or localized copy', () => {
  const retired = [
    /已確認\s*6\s*\/\s*8/,
    /(?:6\s*\/\s*8\s*(?:confirmed|acknowledged)|Acknowledged\s*6\s*\/\s*8)/i,
    /誰已讀懂/,
    /確認回條功能/,
    /摘要(?:最近|近|最多)?\s*300\s*筆/,
    /(?:up to|latest|last)\s*300\s*(?:messages|records)/i,
    /每則(?:翻譯)?(?:後|都)(?:顯示|提醒).*49\s*\/\s*50/,
    /付費版增加完整語言/,
    /need full language coverage/i,
    /confirm receipt, summarize the group/i,
  ];
  for (const name of publicPages) {
    const source = read(name).replace('撤下自動確認人數與摘要 300 筆的未實現宣稱', '撤下未實現宣稱');
    for (const pattern of retired) assert.ok(!pattern.test(source), `${name}: ${pattern}`);
  }
});

test('entry points describe the private and group menu difference without requiring a Bot mention', () => {
  for (const name of ['index.html', 'features.html', 'start.html', 'join.html', 'faq.html', 'blog-line-bot-first-setup.html', 'blog-language-settings.html', 'blog-line-group-translation.html']) {
    const source = read(name);
    assert.match(source, /@選單/, name);
    assert.match(source, /(?:群組固定底部|群組沒有固定底部|群組不支援固定|群組不會固定)/, name);
    assert.match(source, /@語言設定/, name);
    assert.match(source, /@多語/, name);
  }
  const faq = read('faq.html');
  assert.match(faq, /15 分鐘/);
  assert.match(faq, /只限開啟者/);
  assert.match(faq, /全群可見/);
  assert.match(faq, /不用從成員清單標記萬語通/);
});

test('risk guidance distinguishes warnings from invalid input and genuine mentions from typed text', () => {
  const source = read('faq.html') + read('features.html') + read('engine.html');
  for (const pattern of [/手打 @姓名/, /真正提及萬語通 Bot/, /通知.*裝置設定/, /仍提供.*譯文|仍會.*譯文|照常提供.*譯文/, /提醒不是已證實翻錯/, /無效|空白/]) {
    assert.ok(pattern.test(source), `risk scope: ${pattern}`);
  }
});

test('summary and retired reward wording does not disguise its scope', () => {
  const source = read('faq.html');
  assert.match(source, /付費群組並啟用紀錄及摘要/);
  assert.match(source, /實際整理筆數/);
  assert.match(source, /不是所有歷史搜尋或匯出的上限/);
  assert.match(source, /觀看贊助內容換免費額度已停用/);
  assert.match(source, /剩餘 5、3、1、0 則/);
});

test('tutorial and guide references use the current asset revision in all pages', () => {
  for (const name of pages) {
    const source = read(name);
    for (const match of source.matchAll(/(?:src|href)=["']([^"']*assets\/tutorial\/[^"']+)["']/g)) {
      if (/\.(?:mp4|vtt)(?:\?|$)/i.test(match[1])) assert.match(match[1], /20261110.*\?v=content-sync-20261110$/, `${name}: ${match[1]}`);
    }
    for (const match of source.matchAll(/(?:src|href)=["'](assets\/guides\/[^"']+)["']/g)) {
      assert.match(match[1], /\?v=content-sync-20261110$/, `${name}: ${match[1]}`);
    }
  }
});
