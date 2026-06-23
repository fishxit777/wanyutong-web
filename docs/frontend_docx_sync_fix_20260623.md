# 官網 DOCX 同步修正紀錄 2026-06-23

## 依據

- 來源文件：`C:/Users/bao58/OneDrive/Desktop/萬語通優化版.docx`
- 本次修正原因：GitHub Pages 官網仍顯示舊方案、舊比較表、舊推薦/客服資訊。

## 已同步頁面

- `index.html`
  - 比較表從 `NT$99起 / 每日50次` 改為 `NT$0元起 / 中英日韓無限；其他每日50則`。
  - 方案卡與中英文切換 JS 同步免費版、月費版、半年版、一年版、尊爵版。
  - 條款、隱私、退費與 CTA 改為正式 GOOGLE 客服表單 URL。

- `faq.html`
  - 方案與付款入口統一為 `@方案`。
  - 結構化 FAQ 同步最新方案。
  - 移除舊 `買 5 送 1`、`@購買`、舊客服 LINE ID 顯示。

- `join.html`
  - 免費版描述改為「中文、英文、日文、韓文無限翻譯；其他語言每日 50 則」。
  - 語音、圖片 OCR、AI 摘要與每日報表改為升級後完整功能，避免誤導為免費項目。

- `terms.html`、`privacy.html`、`contact.html`、`blog.html` 與各部落格文章 footer
  - 客服資訊改為正式 GOOGLE 客服表單與 Email。
  - 移除舊客服 LINE ID 與舊推薦活動文案露出。

## 驗證

- 已執行 `git diff --check`。
- 已掃描前台 HTML/JS，未再找到舊字串：`@購買`、`LINE ID：fishxit`、`每日50次`、`NT$99起`、`買 5 送 1`、`免費試用`、`介紹新朋友`、`加贈翻譯天數`。
- 因本次 Codex 環境未提供可用 Browser/Chrome 控制工具，且內建 Playwright 缺少 `playwright-core`，未能做實際截圖式手機版渲染；已完成靜態內容與 JS 文案同步檢查。

## 後續待補

- GOOGLE 客服表單正式 URL 已於 2026-06-24 補上：[GOOGLE 客服表單](https://forms.gle/rKatiHrCmh5wpCov8)。
- 操作教學影片如未來恢復製作，再補到 `join.html` 或首頁 CTA 附近。
