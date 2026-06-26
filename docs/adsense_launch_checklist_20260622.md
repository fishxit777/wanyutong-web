# 萬語通官網 AdSense / 廣告串接交接表

更新：2026-06-26

## 本次已完成

- 官網前台新增可開關式廣告設定：
  - `assets/wanyutong-ads-config.js`
  - `assets/wanyutong-ads.js`
- 所有根目錄 HTML 頁面已載入廣告設定檔與廣告載入檔。
- Blog 首頁新增一個內容流廣告位置。
- 每篇 `blog-*.html` 文章新增一個文章內廣告位置。
- `ads.txt` 已保留正式發布商 ID 的替換位置。
- `sw.js` 已更新快取版本並納入廣告設定檔、廣告載入檔、`ads.txt` 與可讀性 CSS。
- 目前預設為 `enabled: false`，所以正式 ID 未補上前不會載入 Google AdSense，也不會顯示空白廣告框。

## 不會放廣告的位置

為避免影響信任感與轉換率，目前設定排除：

- 首頁 `index.html`
- 收費方案頁 `pricing.html`
- 加入 LINE 流程頁 `join.html`
- 開始使用頁 `start.html`

目前只預留 Blog 相關頁面：

- `blog.html`
- `blog-*.html`

## 正式啟用方式

取得 AdSense 發布商 ID 與廣告單元 slot 後，修改：

```js
// assets/wanyutong-ads-config.js
window.WANYUTONG_ADS = {
  enabled: true,
  publisherId: "ca-pub-正式16碼ID",
  slots: {
    blogFeed: "廣告單元slot",
    articleInline: "廣告單元slot"
  }
};
```

然後把 `ads.txt` 替換為 AdSense 提供的正式內容，例如：

```txt
google.com, pub-正式16碼ID, DIRECT, f08c47fec0942fa0
```

注意：

- `publisherId` 要使用 `ca-pub-...`
- `ads.txt` 要使用 `pub-...`
- 不要把範例 ID 上線。

## 外部步驟

這些需要登入 Google / AdSense 後台或有帳號權限，無法只靠本機完成：

- 建立或完成 Google AdSense 帳號。
- 新增網站並送審。
- 取得正式 Publisher ID。
- 建立 Blog 用廣告單元並取得 slot。
- 確認 AdSense 審核結果。
- 若使用自有網域，完成網域、DNS、GitHub Pages `CNAME` 與 HTTPS。

## 法務與體驗原則

- 廣告目前只放內容頁，不放首頁 Hero、價格卡、付款/加入 LINE CTA 旁。
- 隱私權政策已保留 Google AdSense / Cookie 說明。
- 不把 LINE 訊息內容、翻譯內容、付款資料提供給廣告平台做內容販售。
- 若未來加入個人化廣告、再行銷或跨站追蹤，需再次確認隱私權政策文字。

## 驗收清單

- `ads.txt` 可由 `https://網域/ads.txt` 讀取。
- Blog 頁面無正式 ID 時不顯示廣告框。
- 正式 ID 補上後，Blog 頁面能載入 `pagead2.googlesyndication.com`。
- 手機版 Blog 不因廣告位置產生橫向捲動。
- 首頁、收費頁、加入頁不出現第三方廣告。

## 官方參考

- Google AdSense ads.txt 說明：https://support.google.com/adsense/answer/12171612
- Google AdSense Publisher ID 說明：https://support.google.com/adsense/answer/105516
- Google AdSense 廣告單元程式碼說明：https://support.google.com/adsense/answer/9274019
