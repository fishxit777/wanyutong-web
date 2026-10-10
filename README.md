# wanyutong-web

目前版本：2026-10-10。萬語通官網與知識庫的唯一現行來源；LINE Bot 與原生 App 為獨立專案。

## 正式入口

- [官網](https://wanyutong.tw/)
- [八篇核心指南](https://wanyutong.tw/blog.html)
- [完整 OCR 操作與核對表](https://wanyutong.tw/blog-image-ocr-translation.html)
- [方案與購買範圍](https://wanyutong.tw/pricing.html)

## 本版內容

- 圖片如實標示為資訊圖或情境示意，不冒稱實機截圖、影片擷取或測試證據。
- 重複 OCR 指南整合為一篇；舊網址保留無廣告、noindex 的固定導向。
- 文件更新日、程式核對與歷史實測分開，不虛構最新實機或金流驗證。
- 尊爵版維持 NT$2,500／永久買斷／每群組，明列現有功能、付款驗證及未上線項目；不追溯縮減既有訂單權益。
- 官網廣告開關仍關閉；內容修正不代表 AdSense 已核准。

## 保留與清理原則

根目錄 HTML、assets、scripts 為現行頁面、素材、共用程式與重建／驗證工具。檔名日期較早不表示已淘汰；被引用的影片、圖檔、舊網址與測試不得任意刪除。

歷史交接已移出現行專案，保留可回復封存。最新本機交接與清理紀錄留在 docs，不上傳公開網站；公開部署排除 docs、scripts 及本 README。

## 離線驗證

```powershell
python -X utf8 -B -m unittest discover -s scripts -p 'test_*.py'
python -X utf8 -B scripts/audit_site_content.py
$tests = Get-ChildItem -LiteralPath scripts -Filter 'test_*.mjs' | ForEach-Object { $_.FullName }
node --test $tests
git diff --check
```

測試不發送 LINE 訊息、不執行真實付款、不載入真實廣告。發布後另核對正式網站 HTTP 內容及瀏覽器顯示。
