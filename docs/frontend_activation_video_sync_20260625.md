# 萬語通加入開通流程影片嵌入紀錄 2026-06-25

## 需求

- 新增一支「加入開通流程」影片。
- 影片需放在收費方案卡片下方。
- 加入頁也需同步放置，讓使用者掃碼加入後能看到開通流程。

## 影片內容

- Step 01：選擇免費版、月費版、半年版、一年版或尊爵版。
- Step 02：加入萬語通官方 LINE 帳號。
- Step 03：桌機掃 QR，手機點直接加入。
- Step 04：把 Bot 放進群組並依方案開通。
- Ready：開始使用文字、語音、圖片 OCR、摘要與每日報表。

## 官網放置位置

- 首頁：`index.html` 的 `#pricing` 收費方案卡片下方、退費說明上方。
- 加入頁：`join.html` 原「操作教學影片」下方。

## 檔案

- 影片：`assets/wanyutong-activation-flow.mp4`
- 封面：`assets/wanyutong-activation-flow-poster.jpg`
- 影片規格：1280 x 720、H.264 MP4、約 18 秒。

## 快取

- `sw.js` 快取版本更新為 `wanyutong-pwa-20260625-activation-video-1`。
- `CORE_ASSETS` 已加入新 MP4 與 poster。

## 維護提醒

- 若替換影片但沿用同檔名，仍建議更新 `sw.js` 快取版本，避免手機 PWA 顯示舊影片。
- 若流程、方案名稱或付款規則再調整，需同步更新影片內容與本文件。
