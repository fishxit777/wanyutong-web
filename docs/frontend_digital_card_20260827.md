# 萬語通官網數位名片

更新日期：2026-08-27

## 目的

在萬語通官網提供一個可直接分享的品牌數位名片，不公開私人姓名、電話或其他個人識別資料。公開聯絡身分統一使用「萬語通團隊 / WanyuTong Team」。

正式網址：`https://wanyutong.tw/card.html`

## 名片內容

- 正面：品牌、服務定位、核心能力、多語群組翻譯示意。
- 背面：官方 LINE QR、LINE ID、官網、Email 與防詐安全提醒。
- 操作：正反面翻轉、加入官方 LINE、下載 `.vcf` 聯絡人、原生分享或複製網址。
- 顯示：繁體中文／英文、日間／夜間、桌機與手機響應式版面。

## 官網整合

- 首頁頁尾新增「數位名片」。
- 聯絡頁新增數位名片入口並同步中英文切換。
- PWA manifest 新增名片捷徑。
- Service Worker 快取名片頁、樣式與互動程式。
- sitemap 新增 `card.html`。

## 維護邊界

- LINE ID：`@969wpxno`
- 官方網站：`https://wanyutong.tw/`
- 客服信箱：`wanyutong29@gmail.com`
- QR 圖檔：`assets/wanyutong-line-qr.png`
- 品牌標誌：`assets/wanyutong-logo.jpg`
- 禁止在公開名片加入私人姓名、住址、電話、付款資料或帳號憑證。

## 驗證紀錄

- 桌機：1440 x 900，正反面、繁中／英文、日間／夜間通過。
- 手機：390 x 844 與 320 x 800，無水平溢出，服務標籤、聯絡資料、QR 與安全提醒不重疊。
- `manifest.webmanifest` JSON 解析、JavaScript 語法、sitemap XML 與本機資產存在性檢查通過。
