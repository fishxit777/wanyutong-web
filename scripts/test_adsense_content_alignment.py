"""Offline content-truth regression checks; never sends messages or ad requests."""

from __future__ import annotations

import re
import tempfile
import unittest
from datetime import date, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import audit_site_content as audit


ROOT = Path(__file__).resolve().parents[1]


class ContentAlignmentTests(unittest.TestCase):
    # unittest's stock containment assertions echo the whole HTML on failure.
    # Public source can contain account identifiers: fail using fixed labels only.
    def assertIn(self, member, container, msg=None):
        self.assertTrue(member in container, msg or "Expected content fragment missing; document suppressed")

    def assertNotIn(self, member, container, msg=None):
        self.assertFalse(member in container, msg or "Retired content fragment remains; document suppressed")

    def read(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_history_retention_is_not_display_limit_in_both_languages(self):
        text = self.read("faq.html")
        self.assertNotIn("翻譯歷史僅保存", text)
        self.assertNotIn("Translation history stores only", text)
        self.assertGreaterEqual(text.count("最近 100 筆"), 2)
        self.assertIn("most recent 100 records", text)
        self.assertIn("預設顯示最近 20 筆", text)
        self.assertIn("displays the latest 20 records by default", text)
        self.assertIn("不代表付款、使用量或安全稽核", text)

    def test_operations_limits_are_visible_before_payment(self):
        for name in ("faq.html", "pricing.html", "terms.html", "blog-free-paid-plans.html"):
            with self.subTest(page=name):
                text = self.read(name)
                self.assertIn("30–90 秒", text)
                self.assertIn("免費／預付額度", text)
                self.assertIn("2026-09-07", text)
        for name in ("faq.html", "pricing.html", "terms.html"):
            self.assertIn("30–90 seconds", self.read(name), name)

    def test_unlimited_does_not_promise_unlimited_infrastructure(self):
        for name in ("pricing.html", "blog-free-paid-plans.html"):
            with self.subTest(page=name):
                self.assertIn("不限次數是產品用量規則", self.read(name))

    def test_risk_detection_is_limited_to_available_text(self):
        text = self.read("terms.html")
        self.assertNotIn("會自動偵測實際傳送給 Bot 的訊息、圖片及連結", text)
        self.assertNotIn("automatically detects security risks in messages, images, and links", text)
        self.assertGreaterEqual(text.count("既有 OCR 文字"), 2)
        self.assertIn("does not initiate additional paid OCR", text)

    def test_risk_alerts_use_fixed_fields_not_customer_summaries(self):
        text = self.read("terms.html")
        self.assertNotIn("不含客戶原文的去識別摘要", text)
        self.assertNotIn("Threshold events contain de-identified summaries", text)
        self.assertEqual(2, text.count("固定風險分類、事件參考與處理建議"))
        self.assertEqual(2, text.count("不轉送客戶原文或自由格式摘要"))
        self.assertIn("fixed risk categories, event references and handling advice", text)
        self.assertIn("never original customer messages or free-form summaries", text)

    def test_billing_review_does_not_promise_refunds(self):
        for name in ("faq.html", "pricing.html", "terms.html", "blog-free-paid-plans.html"):
            with self.subTest(page=name):
                text = self.read(name)
                self.assertIn("人工查核", text)
                self.assertIn("不保證退款", text)
        for name in ("faq.html", "pricing.html", "terms.html"):
            self.assertIn("does not guarantee a refund", self.read(name), name)

    def test_no_indexable_page_points_to_quarantined_content(self):
        errors: list[str] = []
        audit.audit_internal_links(errors, sorted(ROOT.glob("*.html")))
        self.assertEqual([], errors)

    def test_quarantine_link_variants_are_rejected(self):
        target = sorted(audit.QUARANTINED)[0]
        variants = (
            target,
            target + "#section",
            "/" + target,
            "https://wanyutong.tw/" + target + "?ref=guide#section",
            "//wanyutong.tw/" + target,
            "https://wanyutong.tw/" + target.replace("-", "%2D", 1),
        )
        with tempfile.TemporaryDirectory(prefix="wyt-content-test-") as temp:
            root = Path(temp)
            (root / target).write_text("<p>maintenance</p>", encoding="utf-8")
            page = root / "index.html"
            with patch.object(audit, "ROOT", root):
                for href in variants:
                    with self.subTest(variant=href):
                        page.write_text(f'<a href="{href}">guide</a>', encoding="utf-8")
                        errors: list[str] = []
                        audit.audit_internal_links(errors, [page])
                        self.assertTrue(any("quarantined" in e for e in errors))

    def test_noindex_page_and_external_links_do_not_false_positive(self):
        target = sorted(audit.QUARANTINED)[0]
        with tempfile.TemporaryDirectory(prefix="wyt-content-test-") as temp:
            root = Path(temp)
            (root / target).write_text("<p>maintenance</p>", encoding="utf-8")
            page = root / "index.html"
            with patch.object(audit, "ROOT", root):
                for content in (
                    f'<meta content="noindex,follow" name="robots"><a href="{target}">old guide</a>',
                    f'<a href="https://example.org/{target}">external</a>',
                    '<a href="#section">same page</a>',
                ):
                    page.write_text(content, encoding="utf-8")
                    errors: list[str] = []
                    audit.audit_internal_links(errors, [page])
                    self.assertEqual([], errors)

    def test_review_date_is_a_real_date_not_an_august_literal(self):
        text = self.read("scripts/audit_site_content.py")
        self.assertNotIn('"2026-08-31 review date"', text)
        self.assertIn("fromisoformat", text)

    def test_verification_date_accepts_new_dates_but_rejects_invalid_or_future(self):
        today = date(2026, 9, 7)
        for value, expected in (("2026-09-07", True), ("2026-08-31", True), ("2026-09-08", False), ("2026-02-30", False)):
            with self.subTest(review_date=value):
                content = f'<section class="article-verification"><p>核對 {value}</p></section>'
                self.assertEqual(expected, audit.has_valid_review_date(content, today=today))
        self.assertFalse(audit.has_valid_review_date('<p>2026-09-07</p>', today=today))

    def test_default_review_date_uses_the_site_taipei_day(self):
        with patch.object(audit, "datetime") as clock:
            clock.now.return_value.date.return_value = date(2026, 9, 7)
            content = '<section class="article-verification"><p>核對 2026-09-07</p></section>'
            self.assertTrue(audit.has_valid_review_date(content))
            clock.now.assert_called_once_with(timezone(timedelta(hours=8)))

    def test_link_audit_still_checks_stylesheets(self):
        with tempfile.TemporaryDirectory(prefix="wyt-content-test-") as temp:
            root = Path(temp)
            page = root / "index.html"
            page.write_text('<link rel="stylesheet" href="missing.css">', encoding="utf-8")
            with patch.object(audit, "ROOT", root):
                errors: list[str] = []
                audit.audit_internal_links(errors, [page])
                self.assertTrue(any("broken internal link" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
