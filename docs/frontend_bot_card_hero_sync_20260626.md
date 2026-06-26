# 萬語通首頁 BOT 視覺同步交接 2026-06-26

## 本次目標

- 依使用者指定採用 B 版方向：不再增加左側說明文字，改強化右側 LINE Bot 模擬聊天畫面。
- 右側視覺改為短版重點卡片，避免原本手機長串聊天畫面過假、過長、焦點分散。
- LOGO 統一使用官網正式圖檔 `assets/wanyutong-logo.jpg`。

## 已完成

- `index.html`
  - 首頁 hero 右側改為 `bot-chat-card`。
  - 內容濃縮成三個焦點：主管交辦、萬語通翻譯、確認進度。
  - 新增三個結果標籤：翻譯完成、回覆確認、紀錄可查。
  - 移除舊版 `phone-*` 長手機 mockup HTML、CSS、語系字串與 JS 更新鉤子。
  - 繁中與英文切換同步補齊 `botcard.*` 文案。
  - 手機版針對 390px viewport 做寬度與換行限制，避免橫向爆版。
  - 1365px 桌機寬度以下改用漢堡選單，避免導覽文字被擠成直排。

- `assets/wanyutong-app.js`
  - 手機安全 CSS selector 改為新版 `bot-chat-glow`。
  - 導覽列漢堡門檻同步改為 1450px 以下。
  - 修正 footer 客服表單同步邏輯，移除壞掉的正則，避免外部 JS 語法錯誤。

- `sw.js`
  - PWA 快取版本更新為 `wanyutong-pwa-20260626-bot-card-hero`，降低 GitHub Pages / PWA 舊快取殘留機率。

- `.gitignore`
  - 新增 `_本機作業區_不要上傳/`，避免本機預覽或暫存檔誤上傳。

## 清理

- 已刪除專案內本機暫存資料夾：
  - `_本機作業區_不要上傳/preview_bot_cards/`
- 未刪除正式 assets、docs、HTML、影片或使用者 Downloads / 桌面檔案。
- 已重新掃描 `preview/tmp/temp/old/backup/bak/複本/舊` 類資料夾與檔名，專案內未再發現可刪的舊暫存檔。

## 驗證

- `index.html` 內嵌 script 語法檢查：通過，排除 JSON-LD 後全部可解析。
- `assets/wanyutong-app.js`：`node --check` 通過。
- Chrome desktop 1365x768 截圖檢查：
  - 首頁右側新版 BOT 卡片正常顯示。
  - 導覽列不再擠成直排，改為漢堡選單。
  - H1 無單字落行。
- Chrome desktop 中英文切換檢查：
  - `window.setLang` 已存在且可執行。
  - 中文顯示 `萬語通 BOT / LINE 多國翻譯機器人`。
  - 英文顯示 `WanyuTong BOT / LINE multilingual translation bot`。
- Chrome mobile emulation 390x844 檢查：
  - `scrollWidth=390`
  - `clientWidth=390`
  - BOT 卡片範圍：`left=24`, `right=366`
  - 無水平爆版。

## 後續注意

- 若線上 GitHub Pages 還看到舊手機 mockup，優先清除該站 Service Worker / 瀏覽器快取，或等待 Pages 快取更新。
- 後續若再改首頁 hero，請同步檢查桌機 1365px 與手機 390px。
