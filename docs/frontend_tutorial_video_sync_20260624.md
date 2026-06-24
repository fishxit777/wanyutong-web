# 萬語通官網教學影片嵌入紀錄 2026-06-24

## 依據

- 來源文件：`C:\Users\bao58\OneDrive\Desktop\萬語通優化版.docx`
- 文件指定：底下放操作教學影片，主打方便、簡單、快速理解。
- 影片來源：`C:\Users\bao58\Downloads\影片\wanyutong_3d_three_workers_line_sync_v9_latest.mp4`

## 官網放置位置

- 首頁：`index.html` 的 `#howto` 區塊，放在 4 步驟與群組指令提示下方。
- 加入頁：`join.html` 的 QR Code 加入流程下方。
- 共用影片檔：`assets/wanyutong-line-bot-tutorial.mp4`

## 顯示規則

- 桌機與手機版都使用同一支本機 MP4，不外連。
- 支援瀏覽器原生播放控制、`playsinline`、`preload="metadata"`。
- 繁中標題：`操作教學影片`
- 英文標題：`Setup Tutorial Video`
- 切換語言時，首頁與加入頁文案同步切換。

## 快取與部署

- `sw.js` 已更新快取版本為 `wanyutong-pwa-20260624-tutorial-video-1`。
- `CORE_ASSETS` 已加入 `./assets/wanyutong-line-bot-tutorial.mp4`。

## 後續維護

- 若未來更換影片，維持同一檔名可減少 HTML 修改；若內容大改，請同步更新本文件與 `sw.js` 快取版本。
- 若影片檔變大，需留意 GitHub Pages 載入速度與手機流量。
