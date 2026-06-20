# 官網定位與手機排版修正交接 2026-06-20

## 本次目的

將官網對外主軸從「LINE 群組 AI 翻譯／多語溝通助手」收斂為「跨語言工作交辦、確認與紀錄流程」。萬語通不只賣翻譯，而是協助雇主在 LINE 群組裡完成工作通知、翻譯、收到確認、AI 摘要、每日報表與後台紀錄。

## 已更新範圍

- `index.html`
  - 首頁 title、description、OG/Twitter、JSON-LD。
  - Hero 改為「跨語言工作交辦／有翻譯、有確認、有紀錄」。
  - 功能區改為「不是翻譯 App，是 LINE 工作交辦流程」。
  - 英文版同步改為 work instructions、confirmation、records。
  - 英文語言數修正為 35 languages。
  - 手機排版修正：AI 客服比較表與推薦獎勵表改為卡片式，不再使用過寬表格；右側裝飾與 CTA glow 不再造成手機/桌機溢出。
- `faq.html`
  - FAQ meta、結構化資料、首屏說明、第一題中英文同步改為跨語言工作交辦與確認紀錄工具。
- `join.html`
  - 加入頁 meta、首屏、證明點、動態中英文文案改為「翻譯、確認、紀錄」流程。
- `blog.html`
  - 部落格 meta、JSON-LD、首屏中英文改為跨語言工作交辦、確認與紀錄知識庫。
- `README.md`
  - 新增本交接文件入口。

## 對外文案準則

- 優先使用：跨語言工作交辦、收到確認、AI 摘要、每日報表、後台紀錄、可搜尋紀錄。
- 避免主標再使用：LINE 群組 AI 翻譯、多語溝通助手、只是翻譯 App。
- 翻譯引擎口徑：DeepL 專業翻譯引擎；不要再提 Google 翻譯、雙引擎、自動路由。
- 高風險內容仍需提示人工複核：合約、法律、醫療、財務、安全作業。

## QA 結果

- `git diff --check`：通過。
- `python -m json.tool manifest.webmanifest`：通過。
- 舊文案搜尋：四個主要頁面未再出現 `LINE 群組 AI 翻譯`、`多語溝通助手`、`讓群組聽得懂`、`Try Group Translation`、`36 Languages` 等舊口徑。
- Playwright + Chrome 本機檢查：
  - `index.html`
  - `faq.html`
  - `join.html`
  - `blog.html`
  - 語言：繁中、英文
  - 視窗：1366x900 桌機、390x844 手機
  - 共 16 組，結果 0 failure。
  - 檢查項：預期文案存在、英文版無不該殘留中文、圖片載入正常、頁面無水平溢出、無頁面錯誤。

## 後續注意

- 新增任何 table 前，先設計手機卡片式版面，不要用 `min-width` 讓使用者橫向滑。
- 新增頁面時要同步：
  - 靜態 HTML 預設文案
  - i18n 物件
  - `document.title`
  - meta description / OG description
- 若再次改語言切換，請至少檢查首頁、FAQ、加入頁、部落格四頁的中英文桌機與手機版。
