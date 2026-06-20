# 前台排版與 PWA 檢查交接 2026-06-20

## 範圍

本次只處理 `wanyutong-web` 官網專案，未混入 `11STARS` 後台/Bot/SoundBank 工作。

檢查頁面：

- `index.html`
- `faq.html`
- `blog.html`
- `join.html`
- 8 篇部落格文章頁
- `manifest.webmanifest`
- `sw.js`
- 共用前端腳本 `assets/wanyutong-app.js`

## 已修正

- 手機導覽列：壓縮品牌字、語言切換、主題切換與漢堡按鈕尺寸，避免 360px/390px 寬度外溢。
- 首頁比較表：`#compare` 與 `#vs-competitors` 在手機版改成卡片式表格，並讓中英文欄位標籤同步更新。
- 部落格列表：補齊漢堡按鈕基礎尺寸，並限制卡片內示意訊息在窄螢幕不推出卡片。
- 加入頁 `join.html`：新增中英文切換，和官網共用 `wyt-lang` 語言狀態；桌機與手機文案同步。
- 部落格舊版文章：修正英文版仍顯示「繁中」與中文 title 的問題。
- PWA：新增並驗證 LINE QR 圖與 180/192/512 icon；更新 Service Worker cache 版本；修正不存在的工地文章 JPG 快取路徑。
- 社群預覽：工地文章 `og:image` / `twitter:image` 改用現有 SVG。

## 驗證結果

已用本機 Chrome headless 跑完整前台巡檢：

- 尺寸：1440x900、768x1024、390x844、360x780
- 語系：繁中、英文
- 組合：12 頁 x 4 尺寸 x 2 語系 = 96 組
- 結果：`0` 個排版失敗、`0` 個破圖、英文可見文字 `0` 個中文殘留

已另外確認：

- `python -m json.tool manifest.webmanifest` 通過
- `sw.js` 快取清單內檔案皆存在
- `assets/wanyutong-line-qr.png`、PWA icon 圖檔可正常被圖片函式讀取
- 本地靜態資源掃描未發現缺檔

另以唯讀方式檢查 `萬語通/11STARS` 的 `admin.html`、`admin_competitors.html`、`terms.html`、`privacy.html`、`refund.html`：

- 尺寸：1440x900、768x1024、390x844、360x780
- 組合：5 頁 x 4 尺寸 = 20 組
- 結果：`0` 個排版失敗、`0` 個破圖
- `11STARS` 既有 SoundBank 相關未提交變更未納入本次修改。

## 注意事項

- Chrome console 仍會顯示 Three.js 舊版載入警告，這是外部 CDN 套件版本提醒，不影響本次排版與語系結果。
- Google Fonts 在快速跳頁巡檢時可能出現 `net::ERR_ABORTED`，原因是測試程式立刻切換下一頁造成字型請求中止，非缺檔。
- GitHub Pages 上線後若仍看到舊版，先清除瀏覽器快取或等待 Pages/CDN 更新；本次已同步更新 Service Worker cache 名稱。

## 後續建議

- 下次若再大改首頁或 Blog，至少重跑 360px、390px、768px、1440px 四種尺寸。
- 若要完全消除 Three.js console warning，需改用 ES Module 版 Three.js，屬於另一次前端資產整理工作。
