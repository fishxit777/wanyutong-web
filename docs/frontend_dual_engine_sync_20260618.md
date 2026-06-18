# 官網智慧雙引擎文案同步 2026-06-18

## 目的

配合 LINE Bot 後端改為 DeepL + Google Cloud Translation 智慧雙引擎，官網同步更新前台、FAQ、法律區與中英文切換文案，避免使用者看到「DeepL 單一引擎」或固定「36 種語言」的舊說法。

## 已更新頁面

- `index.html`
  - 首頁功能卡改為 `36+ 語言與智慧雙引擎`。
  - 比較區改為 DeepL + Google Cloud Translation 智慧路由說明。
  - 價格卡中文與英文皆加入智慧雙引擎。
  - 法律區補入 Google Cloud Translation 第三方處理說明。
  - 支援語言清單加入菲律賓文／他加祿文與 `@支援語言` 指令。
  - 中英文切換字典同步更新。
- `faq.html`
  - FAQ 結構化資料、可見文字與中英文切換同步改為智慧雙引擎。
  - 語音翻譯說明從 `再由 DeepL 翻譯` 改為 `再由智慧雙引擎翻譯`。
  - 免責第三方名單加入 Google Cloud Translation。
- `blog.html`
  - 部落格文章卡片標語改為 `36+語言・智慧雙引擎・降低誤解`。
  - 中英文切換字典同步改為 `36+ languages · smart dual engine · fewer misunderstandings`。
  - 已掃描所有 `blog*.html` 文章頁，未發現 DeepL only 或固定 36 種語言的舊口徑。

## 對外口徑

- 使用 `DeepL + Google Cloud Translation 智慧雙引擎`。
- 使用 `36+ 種常用語言`，不要再寫固定 `36 種主要語言`。
- 菲律賓文／他加祿文要列入常用工作語言。
- 重要合約、醫療、法律、財務、工安內容仍需人工複核。

## 驗證

- 已用 `rg` 掃描 `index.html`、`faq.html` 與所有 `blog*.html`，未再找到舊口徑：
  - `DeepL API`
  - `Google 翻譯`
  - `36 種`
  - `36 major`
  - `再由 DeepL`
- 已用本機 Chrome headless 檢查：
  - `index.html` 桌機 1365px / 手機 390px：無整頁水平溢出，無 console/page error。
  - `faq.html` 桌機 1365px / 手機 390px：無整頁水平溢出，無 console/page error。
  - `blog.html` 與 8 篇 `blog-*.html` 文章頁桌機 1365px / 手機 390px：無整頁水平溢出，無 console/page error。
  - `index.html` 手機版比較表本體可橫向捲動，頁面不被撐寬。

## 上線前建議

- 上線後用正式網址複查 `index.html` 的方案卡、比較區、法律區。
- 上線後用正式網址複查 `faq.html` 展開內容是否溢出。
- 上線後用正式網址複查 `blog.html` 與各文章頁中英文切換。
- 若後端尚未設定 `GOOGLE_TRANSLATE_API_KEY`，官網仍可先上線，但對外客服需知道 Google 引擎需等 Render 金鑰補齊才會實際運作。
