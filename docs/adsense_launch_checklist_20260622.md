# 萬語通官網 AdSense 上線清單

日期：2026-06-22

本文件記錄萬語通官網要申請 Google AdSense 的準備狀態、已完成項目，以及需要網站負責人登入帳號後完成的外部步驟。

## 已完成的網站準備

- 新增獨立政策頁：
  - `privacy.html`
  - `terms.html`
  - `contact.html`
- 更新首頁、Blog、FAQ、各篇文章頁的頁尾，讓使用者與 Google 爬蟲能找到政策頁與聯絡方式。
- 新增 `ads.txt` 範本。
- 更新 `sitemap.xml`，加入隱私權政策、使用條款、聯絡方式頁面。
- 更新 `sw.js` 快取版本與核心頁面清單，避免 PWA 舊快取漏掉新頁面。

## 需要負責人登入完成的 5 步

### 1. 購買自有網域

建議優先順序：

1. `wanyutong.com`
2. `wanyutong.tw`
3. `wanyutong.com.tw`

粗估成本：

- `.com`：約 NT$350-700 / 年
- `.tw`：約 NT$800-2,000 / 年
- GitHub Pages 主機：NT$0

注意：目前官網是 `https://fishxit777.github.io/wanyutong-web/`，這是 GitHub Pages 子路徑。AdSense 建帳號時較適合使用自有標準網域，不要使用帶路徑的網址。

### 2. GitHub Pages 綁定自有網域

在 GitHub repo `fishxit777/wanyutong-web`：

1. 進入 `Settings`
2. 進入 `Pages`
3. 在 `Custom domain` 輸入正式網域，例如 `www.wanyutong.com`
4. 儲存
5. 等 DNS 生效後勾選 `Enforce HTTPS`

DNS 設定範例：

```txt
Type: CNAME
Name: www
Value: fishxit777.github.io
```

若使用根網域，例如 `wanyutong.com`，請依 GitHub Pages 官方文件設定 A record 或 ALIAS/ANAME。

### 3. 申請 Google AdSense

到 AdSense 後台：

1. 登入 Google 帳號
2. 新增網站，例如 `wanyutong.com`
3. 填寫付款資訊與所在地
4. 選擇網站驗證方式
5. 取得 AdSense 程式碼或 meta 驗證碼

### 4. 把 AdSense 程式碼放入官網

AdSense 通常會提供類似以下程式碼：

```html
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-0000000000000000"
     crossorigin="anonymous"></script>
```

要貼到主要 HTML 的 `<head>` 內：

- `index.html`
- `blog.html`
- `faq.html`
- `privacy.html`
- `terms.html`
- `contact.html`
- 所有 `blog-*.html`

注意：請不要使用上方 sample ID。一定要使用 AdSense 後台給你的正式 `ca-pub-...`。

### 5. 更新 `ads.txt`

AdSense 會提供類似以下的一行：

```txt
google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0
```

把 `ads.txt` 內的註解範本替換成正式那一行。

完成後，公開網址應可讀到：

```txt
https://你的網域/ads.txt
```

## 建議廣告放置策略

萬語通是服務型官網，首頁主要目標是讓使用者加入 LINE Bot 或聯繫開通。為避免影響成交，建議：

- 首頁：不放或只在頁尾附近放少量自動廣告。
- Blog 列表：可放 1 個橫幅。
- Blog 文章：中段 1 個、文末 1 個。
- FAQ：少量或不放。
- 價格區、加入 LINE 按鈕附近：不要放第三方廣告。

## 送審前檢查

- 自有網域可正常開啟。
- HTTPS 已啟用。
- `privacy.html`、`terms.html`、`contact.html` 可公開瀏覽。
- `sitemap.xml` 可公開瀏覽。
- `ads.txt` 已換成正式發布商 ID。
- 網站沒有空白頁、測試頁、登入牆或明顯亂碼頁。
- AdSense 程式碼已放在有內容、一般訪客會瀏覽的頁面。

## 目前尚未完成原因

以下步驟需要外部帳號登入、付款或 AdSense 後台發布商 ID，因此不能在本機直接完成：

- 購買網域
- GitHub Pages 後台綁定 custom domain
- Google AdSense 帳號申請與付款資料
- 取得正式 `ca-pub-...`
- 送出 AdSense 審查
