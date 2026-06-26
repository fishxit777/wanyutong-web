# 萬語通官網字級與多分頁調整交接

日期：2026-06-26

## 本次處理重點

- 將官網從「主要內容擠在一頁」改為「首頁入口 + 主題分頁」的架構，降低使用者第一眼誤判為詐騙頁的風險。
- 新增共用可讀性樣式 `assets/wanyutong-readable.css`，統一首頁、主題頁、部落格、FAQ、加入頁、條款、隱私、聯絡頁的字級、行高、按鈕、表格與手機寬度。
- 修正手機版橫向溢位，避免部落格、FAQ、首頁卡片、頁腳與按鈕造成左右滑動。
- 放大小字：標籤、日期、頁腳、FAQ 分段、語言切換、日夜按鈕、示意圖小字、表格註記都設定最低可讀字級。
- 移除前台會讓客戶誤解的「後台 / backend / 內部管理 / 管理工具」類字眼，改為服務紀錄、紀錄查詢、客服協助等說法。

## 新增主題分頁

- `features.html`：功能說明
- `industries.html`：適用產業
- `engine.html`：翻譯引擎
- `compare.html`：競品比較
- `pricing.html`：收費方案
- `start.html`：如何開始

首頁 `index.html` 保留品牌第一眼與重點導覽，並新增「依主題看萬語通」入口卡，讓使用者可以依需求進入主題頁，不需要在一頁式長頁中尋找資訊。

## 2026-06-26 追加修正：首頁不再重複放完整區塊

依最新需求，首頁不是「首頁一份完整內容、分頁再一份完整內容」。目前首頁只保留：

- Hero 品牌第一眼
- 四個快速數字摘要
- 主題分頁入口卡
- 短導覽收尾與頁尾

以下完整內容已從首頁移除，需放在對應主題分頁維護：

- 功能說明：`features.html`
- 適用產業與部落格入口：`industries.html`
- 翻譯引擎差異：`engine.html`
- 競品比較：`compare.html`
- 收費方案與加入開通影片：`pricing.html`
- 如何開始、AI 祕書教學與操作流程：`start.html`
- 條款、隱私、退費與客服表單：`terms.html`、`privacy.html`、`contact.html`

後續若新增大型說明區，請優先放進主題分頁；首頁只做入口導覽，不再回到一頁式長頁。

同次補強：

- 所有根目錄 HTML 補上 `assets/icons/wanyutong-icon-192.png` 作為 favicon，避免瀏覽器自動請求 `/favicon.ico` 造成 404。
- 共用 CSS 增加手機英文長字防溢位規則，修正 Blog / FAQ 英文模式在 390px 手機寬度被長標題撐破的問題。

## 同步修改範圍

- `index.html`：主導覽改為獨立頁連結，新增主題入口區，修正中英切換文案。
- `assets/wanyutong-app.js`：導覽與頁腳文字同步改為依 href 判斷，避免不同頁 footer 數量不同時翻譯錯位。
- `sitemap.xml`：加入 6 個主題分頁。
- 所有根目錄 `.html`：載入 `assets/wanyutong-readable.css`。
- `blog.html`、FAQ、加入頁與文章頁：共用字級與手機排版同步受控。

## 後台與提示字眼同步

對應後端專案 `萬語通/11STARS` 已同步調整：

- `admin.html`
- `admin_competitors.html`
- `app.py`

主要方向：管理入口只保留給實際維運，不在客戶面用「後台」描述，改為服務管理入口、服務紀錄、資料檢查、摘要複核等較不突兀的文字。

## 驗證結果

本機靜態伺服器：

```text
http://127.0.0.1:8765
```

使用系統 Chrome + Playwright 檢查以下頁面：

```text
index.html
features.html
industries.html
engine.html
compare.html
pricing.html
start.html
blog.html
faq.html
join.html
terms.html
privacy.html
contact.html
```

檢查 viewport：

```text
desktop 1440x1000
mobile 390x844
```

結果：

- 橫向溢位：0
- 可見文字低於 14px：0
- 首頁英文切換：通過，`html.lang = en`
- 首頁英文導覽：Pricing 正常顯示
- 首頁英文主題區：Explore WanyuTong by Topic 正常顯示
- 2026-06-26 追加驗證：首頁只剩 `hero`、`stats`、`topic-directory`、`home-next` 四個區塊；舊完整內容區塊已從首頁 DOM 移除。
- 2026-06-26 追加修正：依「整個原封不動轉移到分頁」要求，使用 Git 上一版首頁內容作為來源，將原首頁完整區塊直接搬入對應主題頁，不再使用精簡版或重寫版：
  - `features.html`：`workplace-os`、`features`
  - `industries.html`：`industries`、`guides`
  - `engine.html`：`compare`、`ai-service-fit`
  - `compare.html`：`vs-competitors`
  - `pricing.html`：`pricing`
  - `start.html`：`setup-flow`、`howto`
  - `terms.html`：`terms`
  - `contact.html`：`cta`
- 2026-06-26 追加驗證：上述 9 個頁面 × 桌機/手機 × 繁中/英文，共 36 組 Playwright 檢查通過；首頁不含 `workplace-os`、`pricing`、`terms` 等完整內容區塊，分頁均含指定原始區塊，橫向溢位 0。
- 2026-06-26 追加驗證：13 個頁面 × 桌機/手機 × 繁中/英文，橫向溢位 0、JS error 0、HTTP 404 0。
- 舊一頁式錨點搜尋：未發現
- 客戶面「後台/backend」等字眼搜尋：未發現

## 後續注意

- 若新增頁面，需在 `<head>` 引入 `assets/wanyutong-readable.css`。
- 若新增導覽項目，需同步更新 `assets/wanyutong-app.js` 的 href 對應翻譯。
- 若線上 GitHub Pages 還看到舊版，通常是尚未 commit/push 或瀏覽器快取，請加查詢字串測試，例如 `index.html?qa=1`。
