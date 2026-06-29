# 萬語通官網 AdSense / 廣告串接交接表
更新日：2026-06-30

## 目前決策

網站廣告採「內容廣告」策略，只放在 Blog 與文章內容頁，不放首頁、收費方案、加入 LINE、開始流程、付款或免費額度解鎖頁。

LINE Bot 免費版額度用完時，使用「觀看贊助內容解鎖繼續使用」的自家頁面，不要求使用者點擊 Google AdSense 廣告，也不把第三方廣告點擊和翻譯額度直接綁定。

## 已完成的前台檔案

- `assets/wanyutong-ads-config.js`
  - 廣告總開關與正式 AdSense ID / slot 填寫處。
  - `mode: "content_ads_only"`，明確限制為內容頁廣告。
  - `excludedPaths` 已排除 `index.html`、`pricing.html`、`join.html`、`start.html`、`free-unlock`。
- `assets/wanyutong-ads.js`
  - 只有 publisher ID 格式正確、slot 是數字、路徑符合 Blog 白名單時才載入 AdSense。
  - 缺少正式 ID 或 slot 時會隱藏廣告框，不顯示空白區塊。
  - 提供 `window.wytAds.status()` 方便在瀏覽器 console 檢查狀態。
- `ads.txt`
  - 已保留正式 publisher ID 的替換位置。
- `sw.js`
  - 已更新快取版本，避免手機或 PWA 繼續拿舊的廣告設定。

## 現在不會顯示廣告的原因

正式 AdSense publisher ID 與廣告單元 slot 尚未填入，因此即使頁面已經有廣告框架，也不會載入 Google AdSense。

這是故意的，避免使用假 ID、錯誤 ID 或未核准帳號造成審核與收益問題。

## 正式上線時只改這兩處

1. 修改 `assets/wanyutong-ads-config.js`

```js
window.WANYUTONG_ADS = {
  enabled: true,
  mode: "content_ads_only",
  publisherId: "ca-pub-你的16位數發布商ID",
  slots: {
    blogFeed: "Blog列表廣告slot",
    articleInline: "文章內廣告slot"
  }
};
```

2. 修改 `ads.txt`

```txt
google.com, pub-你的16位數發布商ID, DIRECT, f08c47fec0942fa0
```

注意：

- `publisherId` 使用 `ca-pub-...`。
- `ads.txt` 使用 `pub-...`。
- 兩個數字要一致，不要填測試值或假值。

## 廣告位置

允許：

- `blog.html`
- `blog-*.html`

排除：

- `index.html`
- `pricing.html`
- `join.html`
- `start.html`
- `free-unlock`
- 任何付款、加入 LINE、方案 CTA 旁邊的位置

## Bot 免費版解鎖規則

目前 Bot 端使用的是「贊助內容頁」：

- 免費額度用完時，提示使用者可自願觀看贊助內容。
- 觀看一次可加贈少量翻譯額度。
- 每日可領取次數有限制。
- 不要求點擊第三方廣告。
- 未來若要接正式獎勵廣告平台，必須另依該平台政策設計，不直接套用 AdSense 內容廣告。

## 驗證方式

在瀏覽器 console 執行：

```js
window.wytAds.status()
```

未填正式 ID 前應看到：

```js
{
  enabled: false,
  mode: "content_ads_only",
  hasPublisher: false
}
```

填入正式 ID 與 slot 後，在 Blog 頁應看到：

- `enabled: true`
- `hasPublisher: true`
- Network 會載入 `pagead2.googlesyndication.com`
- Blog 頁出現正式廣告
- 首頁、方案頁、加入頁不出現廣告

## 仍需人工完成

這些需要登入 Google / AdSense 後台：

- 完成 AdSense 帳號與網站審核。
- 取得 publisher ID。
- 建立 Blog 用廣告單元並取得 slot。
- 把正式 `ads.txt` 發布後，回 AdSense 檢查是否通過。
- 觀察審核結果與收益狀態。

## 官方參考

- Google AdSense Program policies：https://support.google.com/adsense/answer/48182
- Google AdSense ads.txt 說明：https://support.google.com/adsense/answer/12171612
- Google AdSense Publisher ID 說明：https://support.google.com/adsense/answer/105516
- Google AdSense 廣告單元程式碼說明：https://support.google.com/adsense/answer/9274019
