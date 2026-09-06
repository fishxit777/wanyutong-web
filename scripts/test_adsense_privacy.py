"""Local disclosure checks, not a certification of legal or AdSense compliance."""
import unittest
from pathlib import Path
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]


class PrivacyDocument(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.links = set()
        self.text = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.add(dict(attrs).get("href", ""))

    def handle_data(self, data):
        self.text.append(data)


class PrivacyDisclosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = PrivacyDocument((ROOT / "privacy.html").read_text(encoding="utf-8"))
        cls.text = " ".join(cls.page.text)

    def test_third_party_ad_use_is_explicit(self):
        for term in ("Google", "第三方", "Cookie", "先前", "其他網站", "網路信標", "IP"):
            self.assertTrue(term in self.text, "missing third-party data-use topic")

    def test_opt_out_and_google_data_links(self):
        for href in ("https://www.google.com/settings/ads/",
                     "https://www.aboutads.info/choices/",
                     "https://policies.google.com/technologies/partner-sites?hl=zh-TW"):
            self.assertTrue(href in self.page.links, "missing public privacy-control link")

    def test_no_unsupported_blanket_image_scanning(self):
        self.assertFalse("會自動偵測訊息、圖片及連結的安全風險" in self.text, "stale image-scan claim")
        self.assertTrue("未取得文字的圖片" in self.text, "missing image limitation")
        self.assertTrue("不會另外呼叫付費 OCR" in self.text, "missing OCR scope")

    def test_notification_disclosure_is_current(self):
        for term in ("固定風險分類", "不轉送客戶原文", "唯一私人管理員"):
            self.assertTrue(term in self.text, "missing current notification boundary")

    def test_ad_status_not_pretended_approved(self):
        for term in ("尚未啟用廣告投放", "不代表 Google 已核准", "不會取代同意管理機制"):
            self.assertTrue(term in self.text, "missing advertising activation boundary")

    def test_scope_of_analytics_minimization(self):
        for term in ("頁面與來源欄位", "來源網域", "不保存來源網址的路徑或查詢參數",
                     "自有流量紀錄仍包含瀏覽器資訊、來源 IP 與時間", "不代表完全不收集 IP"):
            self.assertTrue(term in self.text, "missing analytics scope distinction")
        self.assertFalse("自有瀏覽統計以公開頁名與來源網域為限" in self.text,
                         "must not imply that own analytics excludes technical records")


if __name__ == "__main__":
    unittest.main()
