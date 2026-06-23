# 萬語通官網 LOGO 同步交接 2026-06-24

## 本次更新

- 新增官網共用 LOGO 資產：`assets/wanyutong-logo.jpg`
- LOGO 來源：`C:\Users\bao58\Downloads\圖片\萬語通LOGO.jpg`
- 首頁第一屏新增大型品牌 LOGO 區塊，文字為「萬語通 / LINE多國翻譯機器人」，英文版為「WanyuTong / Globe Talk AI Translation」。
- 導覽列品牌改為「LOGO 圖片 + 萬語通 / WanyuTong」。
- 同步頁面：`index.html`、`blog.html`、所有 `blog-*.html`、`faq.html`、`join.html`、`contact.html`、`privacy.html`、`terms.html`。
- Open Graph / Twitter 分享圖改用 `assets/wanyutong-logo.jpg`。

## 技術注意

- `assets/wanyutong-app.js` 會在頁面載入與語言切換時重建品牌區，已改為保留並補上 `.brand-logo`，避免切換中英文後 LOGO 被純文字覆蓋。
- 手機版首頁已調整順序，品牌 LOGO 與主標優先出現在第一屏，手機 mockup 往下排列。

## 已驗證

- `git diff --check` 通過。
- 本機 `http://127.0.0.1:8765/index.html` 檢查：
  - 桌機：導覽列 LOGO 與首頁大 LOGO 載入成功，無水平溢出。
  - 中文切換：LOGO 保留，文字同步為「萬語通 / LINE多國翻譯機器人」。
  - 手機 390x844：首頁大 LOGO 在第一屏內，無水平溢出。
  - Blog、FAQ、文章頁抽查：LOGO 載入成功，無水平溢出。
  - Browser console 無錯誤。
