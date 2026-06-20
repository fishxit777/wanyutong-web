# 官網 DeepL 單引擎文案同步 2026-06-20

## 決策

官網取消舊備援翻譯引擎與雙引擎對外說法，統一改為 DeepL 專業翻譯引擎。中英文版、FAQ、Blog、條款、隱私、價格卡、比較表與手機版生成資料都要維持一致。

## 已調整範圍

- `index.html`
  - 首頁功能、統計、比較表、價格卡、支援語言、條款、隱私與中英文切換字典。
  - 手機版價格卡與比較表生成資料同步改為 DeepL-only。
- 舊引擎顯示改為 `Translation Engine`。
- `faq.html`
  - SEO keywords、FAQ JSON-LD、可見 FAQ、中文/英文字典與免責供應商名單。
- `blog.html`
  - Blog 卡片標語與中英文切換字典。

## 對外文案規則

- 中文使用：`DeepL 專業翻譯引擎`、`35 種常用語言`。
- 英文使用：`DeepL professional translation engine`、`35 common languages`。
- 不再使用舊備援翻譯、雙引擎、自動路由或浮動加號語言數等舊口徑。
- 不再把已移除的舊語言項目列為目前翻譯語言賣點。

## 保留項目

- Google Fonts：僅為字型載入，不屬於翻譯服務。
- Google Search Console 驗證檔：僅為網站驗證，不屬於翻譯服務。

## 驗證重點

部署前後應確認正式頁面不得再出現舊備援翻譯、雙引擎、自動路由或浮動加號語言數等舊口徑。
