# AdSense 內容品質重整設計

## 目標

在不誤動 LINE Bot、付款或正式資料庫的前提下，將萬語通官網從「技術可抓取但內容可信度不足」整理成可核對、可重現、說法一致的產品網站。這次不保證 AdSense 必然核准，但要移除目前可證實的內容風險，並建立第 6 次送審前的客觀門檻。

## 已確認事實

- `wanyutong.tw`、`ads.txt`、`robots.txt` 與 `sitemap.xml` 可正常存取。
- 正式 Bot 程式將免費方案定義為：中文、英文、日文、韓文不限次數；其他支援語言每日 50 則。
- 正式 Bot 公開支援 36 種常用語言；實際清單以 Bot 的 `@支援語言` 回覆為準。
- 月費、半年、一年與尊爵方案的功能仍以正式方案頁與付款入口為準。
- AdSense 第 5 次退件頁只顯示通用的計畫政策原因，沒有提供具體子條款。

## 採用方案

採用「保留強頁、隔離弱頁、重寫核心內容」方案。

1. 五篇高風險舊文章改成 `noindex,follow`，移出 Blog 首頁與 Sitemap，並移除 AdSense 程式；網址保留，避免直接產生 404。
2. 三篇核心舊文章改寫成單一繁體中文主文，不再同頁塞入大段重複英文版本；另強化兩篇現有核心教學。
3. 首頁及共用翻譯字典移除無法證明的 `0.3 秒`，把模擬畫面中的 `Official` 改成不帶認證暗示的產品標示。
4. 所有核心文章標示核對日期、適用方案、畫面來源、已知限制與人工覆核責任。
5. 高風險主題只提供一般溝通流程，並連結勞動部、職安署、LINE Developers 等第一方來源。

## 隔離範圍

- `blog-caregiver-line-translation.html`
- `blog-construction-line-translation.html`
- `blog-factory-line-translation.html`
- `blog-foreign-worker-safety-law.html`
- `blog-restaurant-foreign-worker-translation.html`

這些頁面暫時保留網址，但不列入可索引內容與廣告範圍。內容改為簡短說明與可用替代指南，後續只有在完成獨立資料、實測流程與來源補強後才恢復。

## 核心內容範圍

- `blog-line-group-translation.html`：LINE 群組翻譯實際顯示方式、設定、演練與限制。
- `blog-image-ocr-translation.html`：圖片 OCR 適用情況、拍攝、人工核對與隱私。
- `blog-foreign-worker-communication.html`：跨語言交班與回覆流程；勞動權益導向 1955 官方資源。
- `blog-line-bot-first-setup.html`：第一次使用流程、公開指令與失敗排查。
- `blog-free-paid-plans.html`：免費與付費方案事實表、選擇情境與付款安全。

## 重新送審門檻

- 隔離頁不在 Blog 索引與 Sitemap，沒有 AdSense 程式，且含 `noindex,follow`。
- 全站不存在 `0.3秒`、`0.3s` 產品速度宣稱或誤導性的認證標示。
- 免費額度、語言數量、付費功能與正式 Bot 程式一致。
- 核心文章都有唯一標題、Canonical、H1、Article 結構化資料、核對日期與限制說明。
- 自動化內容稽核、內部連結檢查及本機手機版視覺驗收通過。
- 正式網站部署完成，Sitemap 已更新，Google 已有時間重新抓取新版頁面。
- 上述條件未完成前，不操作 AdSense 的重新提交按鈕。

