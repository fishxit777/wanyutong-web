# 萬語通三支教學影片重製交接

更新日期：2026-09-14
維護單位：萬語通團隊

## 目標

依目前正式官網與 LINE Bot 行為重製三支教學影片，取代所有舊版本。新版不使用客戶對話、個人資料或付款畫面，以品牌動態圖卡呈現可重現的操作流程。

## 現役影片資產

| 主題 | 影片 | 封面 | WebVTT |
|---|---|---|---|
| LINE Bot 操作 | `assets/wanyutong-line-bot-tutorial-20260914.mp4` | `assets/wanyutong-line-bot-tutorial-20260914-poster.jpg` | `assets/wanyutong-line-bot-tutorial-20260914.vtt` |
| AI 祕書 | `assets/wanyutong-secretary-tutorial-20260914.mp4` | `assets/wanyutong-secretary-tutorial-20260914-poster.jpg` | `assets/wanyutong-secretary-tutorial-20260914.vtt` |
| 方案與開通 | `assets/wanyutong-activation-flow-20260914.mp4` | `assets/wanyutong-activation-flow-20260914-poster.jpg` | `assets/wanyutong-activation-flow-20260914.vtt` |

輸出以 1920×1080、16:9、H.264／AAC、網頁快速啟播為基準。畫面已燒錄繁體中文字幕，另提供可手動開啟的繁中 WebVTT 字幕軌；字幕軌不設為預設，避免與燒錄字幕重疊。

## 免費重製方式

- 必要工具：Python、Pillow、Edge TTS、FFmpeg 與 ffprobe；輸出與暫存目錄須放在 OneDrive 外。
- 重製全部影片：`python scripts/build_tutorial_videos.py --repo-root . --work-dir C:\WanyuTongMedia\video-build`
- 只重製單一主題可加上 `--only line-bot-tutorial`、`--only secretary-tutorial` 或 `--only activation-flow`。
- 規格驗證：`python scripts/test_tutorial_video_specs.py`；網站引用與快取驗證：`node --test scripts/test_tutorial_video_assets.mjs`。
- Canva 可用於人工視覺草稿；目前連線工具未提供影片時間軸、配音同步及 MP4 匯出的完整自動控制，因此正式可重現產線仍以本機工具為準。

## 內容依據

### LINE Bot 操作

- `@新手教學` 與 `@說明` 為公開教學入口。
- 有效的 `@語言設定 語言A 語言B` 切換雙語並自動關閉持續多語；輸入無效時保留原模式。
- `@多語` 在個人與群組皆為持續設定，最多同時 8 種語言。
- 以 `@多語 關閉` 回到原雙語，或用有效的 `@語言設定` 直接切換新雙語。
- 總支援 36 種常用語言，不代表可同時選取 36 種；群組所有成員看到同一份翻譯結果。

### AI 祕書

- AI 祕書為付費群組功能，依序介紹說明、狀態、摘要與報表。
- 只整理已記錄的群組內容，整理筆數及可用功能依方案。
- 重要交辦、金額、合約與安全事項仍須由管理者人工確認。

### 方案與開通

- 免費版為中文、英文、日文、韓文不限次；其他語言每日 50 則。
- 付費方案與期間依官網現行方案呈現；實際金額、期間與是否續扣以送出前的正式訂購畫面為準。
- 先將 Bot 加入目標群組，再傳 `@方案`，只使用群組內 Bot 產生的官方連結。
- 付款成功後只開通或延長該付款群組；若超過合理處理時間仍未生效，使用 `@客服`。

## 官網整合

- `features.html`：LINE Bot 操作影片與 AI 祕書影片。
- `join.html`：LINE Bot 操作影片與方案開通影片。
- `pricing.html`：方案開通影片。
- 三頁均使用版本化的 MP4／poster／VTT，並同步繁中及英文影片說明。

## PWA 與效能

- service worker 版本：`wanyutong-pwa-20260914-public-status-copy-v2`。
- HTML、poster、VTT 與必要靜態資產在安裝時預快取。
- 三支 1080p MP4 不在 `CORE_ASSETS`，只列入 `RUNTIME_MEDIA_ASSETS`，避免安裝 PWA 時一次下載全部影片。
- 一般瀏覽器影片播放使用 Range 串流，直接交由瀏覽器與伺服器處理，不把不完整的 206 回應寫入 Cache Storage；只有少數完整、非 Range 的 200 回應才可進入既有執行期快取。

## 驗證規則

1. 三個頁面不得再引用舊日期或無日期的影片與封面。
2. 每個 `<video>` 必須有 20260914 的 MP4、poster 與繁中 WebVTT。
3. VTT 需以 `WEBVTT` 開頭，且不得含客戶內容或個人資料。
4. 自動測試必須確認 MP4 不在安裝預快取清單，但仍在執行期 allowlist。
5. 發布前以 `ffprobe` 核對 1920×1080、H.264、AAC、時長與檔案大小，並抽查片頭、中段、片尾及音量。
6. 新版測試完成後移除所有被取代的舊二進位素材；Git 歷史保留可回復性。

## 2026-09-14 對外說法修正

- 三支影片同步移除免費主機、429、額度與黃色事件等內部技術分類。
- 對外統一說明：短暫延遲先稍候再試，持續發生時透過官方客服反映；查核確認為資安事件時，通知萬語通系統管理員處理。
- 內部黃色平台營運事件與紅色資安事件的判定規則不變，本次只調整公開影片的說法。
- MP4 與 VTT 引用加入 `public-status-v2` 內容版號，避免舊訪客的瀏覽器 HTTP 快取繼續播放前一版。

## 範圍限制

本輪只更新官網影片、字幕、封面、嵌入文案、PWA 快取與測試；不修改 LINE Bot 後端、付款 callback、方案代碼、付款方式、會員資料或對外群發。
