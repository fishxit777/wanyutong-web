"""Offline regression for truthful editorial updates; no live ad/LINE/payment calls."""

from __future__ import annotations

import json
import re
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATE = "2026-10-10"
MERGED = "blog-image-ocr-checklist.html"
DESTINATION = "blog-image-ocr-translation.html"
GUIDES = (
    "blog-line-bot-first-setup.html", "blog-language-settings.html",
    "blog-line-group-translation.html", "blog-group-translation-checklist.html",
    "blog-foreign-worker-communication.html", "blog-translation-quality-checklist.html",
    "blog-image-ocr-translation.html", "blog-free-paid-plans.html",
)


class VisibleContent(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.text = []
        self.anchors = []
        self.hidden_depth = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in ("script", "style"):
            self.hidden_depth += 1
        if tag == "a":
            self.anchors.append(values.get("href", ""))

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden_depth = max(0, self.hidden_depth - 1)

    def handle_data(self, data):
        if not self.hidden_depth:
            self.text.append(data)


class ContentRefreshTests(unittest.TestCase):
    # Never include full HTML/account metadata in assertion error output.
    def assertIn(self, member, container, msg=None):
        self.assertTrue(member in container, msg or "Expected content fragment missing")

    def assertNotIn(self, member, container, msg=None):
        self.assertFalse(member in container, msg or "Retired fragment remains")

    def assertRegex(self, text, regex, msg=None):
        self.assertTrue(re.search(regex, text), msg or "Expected pattern missing; document suppressed")

    def read(self, name):
        return (ROOT / name).read_text(encoding="utf-8")

    def test_diagrams_are_not_claimed_as_video_captures(self):
        for name in GUIDES + ("blog.html",):
            source = self.read(name)
            with self.subTest(page=name):
                for old in ("畫面取自萬語通實際教學影片", "教學流程中的去識別化操作畫面",
                            "This screen comes from the WanyuTong tutorial"):
                    self.assertNotIn(old, source)
                if "assets/guides/" in source:
                    self.assertRegex(source, r"示意圖|資訊圖")

    def test_updated_guides_separate_document_update_from_live_tests(self):
        for name in GUIDES:
            source = self.read(name)
            visible = " ".join(VisibleContent(source).text)
            with self.subTest(page=name):
                self.assertIn(UPDATE, visible)
                self.assertRegex(visible, r"文件|文案|內容更新|內容與程式核對")
                self.assertRegex(visible, r"(?:非|未|不代表|不是|沒有).*?(?:實測|測試)")
                blocks = re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', source, re.S)
                articles = [json.loads(block) for block in blocks if json.loads(block).get("@type") == "Article"]
                self.assertEqual(1, len(articles))
                self.assertEqual(UPDATE, articles[0]["dateModified"])

    def test_ocr_checklist_is_consolidated_and_has_no_ads(self):
        source = self.read(MERGED)
        self.assertRegex(source, r'name=["\']robots["\'][^>]*content=["\']noindex,\s*follow')
        self.assertRegex(source, rf'rel=["\']canonical["\'][^>]*href=["\']https://wanyutong.tw/{DESTINATION}')
        self.assertIn(DESTINATION + "#checklist", source)
        for fragment in ("wanyutong-ads", "data-wyt-ad", "pagead2.googlesyndication.com"):
            self.assertNotIn(fragment, source)
        self.assertIn('id="checklist"', self.read(DESTINATION))

    def test_active_internal_links_do_not_send_users_through_merged_page(self):
        for path in ROOT.glob("*.html"):
            source = path.read_text(encoding="utf-8")
            if path.name == MERGED or re.search(r'content=["\']noindex', source):
                continue
            self.assertFalse(any(MERGED in href for href in VisibleContent(source).anchors), path.name)

    def test_sitemap_and_pwa_exclude_redirect_but_keep_main_guide(self):
        sitemap = ET.fromstring(self.read("sitemap.xml"))
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = {node.find("s:loc", ns).text: node.find("s:lastmod", ns).text for node in sitemap}
        self.assertNotIn("https://wanyutong.tw/" + MERGED, urls)
        for name in GUIDES + ("blog.html", "editorial.html", "pricing.html", "faq.html", "terms.html"):
            self.assertEqual(UPDATE, urls["https://wanyutong.tw/" + name], name)
        worker = self.read("sw.js")
        self.assertIn("20261010-content-truth-v1", worker)
        self.assertNotIn("'./" + MERGED + "'", worker)
        self.assertIn("'./" + DESTINATION + "'", worker)

    def test_pricing_preserves_amount_and_marks_future_languages(self):
        for name in ("pricing.html", "blog-free-paid-plans.html", "faq.html", "terms.html"):
            source = self.read(name)
            visible = " ".join(VisibleContent(source).text)
            with self.subTest(page=name):
                self.assertRegex(visible, r"2,?500|2500")
                self.assertIn("每群組", visible)
                self.assertIn("台語", visible)
                self.assertIn("客語", visible)
                self.assertRegex(visible, r"不.*(?:已交付|包含|保證|承諾)|尚未.*(?:提供|交付)")
                self.assertNotIn("已完成真實付款測試", source)
        self.assertNotIn("<li>預計開發台語版、客語版</li>", self.read("pricing.html"))

    def test_knowledge_hub_has_eight_unique_guides(self):
        source = self.read("blog.html")
        self.assertEqual(8, len(re.findall(r'<a class="knowledge-card"', source)))
        self.assertIn("核心指南：8 篇", source)
        self.assertNotIn(MERGED, source)


if __name__ == "__main__":
    unittest.main()
