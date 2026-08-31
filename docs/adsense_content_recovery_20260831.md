# AdSense 內容品質重整交接（2026-08-31）

## 結論

這次不是只檢驗。官網內容已實際重整，目標是移除薄弱、重複、無法持續證實或可能誤導的內容，建立可被讀者與搜尋引擎核對的核心文章與產品事實。

目前只完成網站內容與技術品質修正，不代表 Google AdSense 一定核准。2026-08-31 已確認為第五次未核准；本次部署後不立即進行第六次送審，先保留重新抓取與索引觀察期。

## 已完成修正

- 將部落格首頁改為 9 篇可核對的核心內容入口，移除大量重複卡片與薄弱導流。
- 完整重寫三篇支柱文章：LINE 群組翻譯、圖片 OCR 翻譯、外籍員工溝通。
- 補強首次設定與免費／付費方案文章的日期、限制、來源與實際指令。
- 五篇無法在本輪充分證實的舊文章改為透明維護頁，設定 `noindex,follow`、移出 sitemap、移除廣告程式，但保留舊網址與安全導流。
- 重寫工具比較頁，不保留無第一方證據的競品價格、免費額度、排名或勝負。
- 清除八個舊語系字典中殘留的競品名稱、價格、額度及「只有 8 種語言」舊資料。
- 將引擎比較改為流程比較；第三方功能與價格一律要求回到各服務官網核對。
- 全站移除無法證實的 `0.3 秒`速度承諾，改為先測再用與依實際狀況說明。
- 統一公開事實：中文、英文、日文、韓文文字翻譯不限次數；其他支援語言每日 50 則；共 36 種常用工作語言，實際以 Bot `@支援語言` 與付款頁為準。
- 修正首頁手機英文標題斷字、示意圖揭露與假 `Official` 標籤。
- 新增可重複執行的 `scripts/audit_site_content.py`，防止薄弱頁、錯誤連結與已淘汰聲明回歸。

## 隔離頁面

- `blog-caregiver-line-translation.html`
- `blog-construction-line-translation.html`
- `blog-factory-line-translation.html`
- `blog-foreign-worker-safety-law.html`
- `blog-restaurant-foreign-worker-translation.html`

## 驗收結果

執行：

```text
python scripts/audit_site_content.py
PASS: content structure, internal links, quarantine rules, pillar evidence, and banned-claim checks all passed
Checked 31 HTML files, 5 pillar pages, and 5 quarantine pages
```

另執行 `git diff --check`，無空白錯誤。瀏覽器驗收涵蓋首頁、部落格首頁、三篇支柱文章、方案頁、工具比較頁、引擎頁及一篇隔離頁；桌機與 390 × 844 手機視窗均無橫向溢出或破圖。引擎頁繁中／英文切換後也未恢復舊競品資料。

## 部署與觀察

- 部署分支：`codex/adsense-content-recovery`
- 正式分支／內容提交：`main` / `955d815`
- 正式網址：<https://wanyutong.tw/>
- 2026-08-31 已以正式網域驗證首頁、知識庫、工具比較、引擎頁、三篇支柱文章、方案頁、隔離頁與 sitemap，共 10 個檢查全部通過。
- 已建立 Codex heartbeat `adsense`，自 2026-09-07 起每週一 10:00 唯讀檢查公開索引與可用的 AdSense 狀態。
- 本輪不執行第六次 AdSense 重新提交。
- 建議至少等待核心頁重新抓取並觀察搜尋摘要，再由管理員確認是否送審。

## 範圍界線

本次只修改 `wanyutong-web` 官網。未修改 LINE Bot 後端、付款流程、Gmail、Render 正式服務或正式資料庫。
