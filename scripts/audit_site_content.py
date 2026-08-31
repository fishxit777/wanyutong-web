#!/usr/bin/env python3
"""Repeatable content, trust, and link audit for the WanyuTong static site."""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
QUARANTINED = {
    "blog-caregiver-line-translation.html",
    "blog-construction-line-translation.html",
    "blog-factory-line-translation.html",
    "blog-foreign-worker-safety-law.html",
    "blog-restaurant-foreign-worker-translation.html",
}
PILLARS = {
    "blog-line-group-translation.html": "developers.line.biz",
    "blog-image-ocr-translation.html": "developers.line.biz",
    "blog-foreign-worker-communication.html": "fw.wda.gov.tw",
    "blog-line-bot-first-setup.html": "developers.line.biz",
    "blog-free-paid-plans.html": "付款",
}
SKIP_STRUCTURE = {"google3ba367f41a0000ba.html"}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text, flags=re.IGNORECASE | re.DOTALL))


def audit_structure(errors: list[str], html_files: list[Path]) -> None:
    for path in html_files:
        if path.name in SKIP_STRUCTURE:
            continue
        text = path.read_text(encoding="utf-8")
        robots_match = re.search(
            r'<meta\s+[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']+)',
            text,
            flags=re.IGNORECASE,
        )
        is_noindex = bool(robots_match and "noindex" in robots_match.group(1).lower())
        if count(r"<title\b", text) != 1:
            fail(errors, f"{path.name}: expected exactly one <title>")
        if count(r"<link\s+[^>]*rel=[\"']canonical[\"']", text) != 1:
            fail(errors, f"{path.name}: expected exactly one canonical link")
        if count(r"<h1\b", text) != 1:
            fail(errors, f"{path.name}: expected exactly one <h1>")
        if not is_noindex and not re.search(r'<meta\s+[^>]*name=["\']description["\']', text, re.I):
            fail(errors, f"{path.name}: indexable page is missing a meta description")


def audit_internal_links(errors: list[str], html_files: list[Path]) -> None:
    for path in html_files:
        text = path.read_text(encoding="utf-8")
        for raw_href in re.findall(r'href=["\']([^"\']+)', text, flags=re.IGNORECASE):
            href = unquote(raw_href.strip())
            if not href or href.startswith(("#", "http://", "https://", "mailto:", "tel:", "javascript:")):
                continue
            target_path = urlsplit(href).path
            if not target_path:
                continue
            target = (path.parent / target_path).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                fail(errors, f"{path.name}: internal link escapes site root: {raw_href}")
                continue
            if not target.exists():
                fail(errors, f"{path.name}: broken internal link: {raw_href}")


def audit_local_assets(errors: list[str], html_files: list[Path]) -> None:
    for path in html_files:
        text = path.read_text(encoding="utf-8")
        for raw_src in re.findall(r'<(?:img|script)\b[^>]*\bsrc=["\']([^"\']+)', text, flags=re.IGNORECASE):
            src = unquote(raw_src.strip())
            if not src or src.startswith(("http://", "https://", "data:")):
                continue
            target_path = urlsplit(src).path
            target = (path.parent / target_path).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                fail(errors, f"{path.name}: local asset escapes site root: {raw_src}")
                continue
            if not target.exists():
                fail(errors, f"{path.name}: missing local asset: {raw_src}")


def audit_json_ld(errors: list[str], html_files: list[Path]) -> None:
    for path in html_files:
        text = path.read_text(encoding="utf-8")
        blocks = re.findall(
            r'<script\s+[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        for index, block in enumerate(blocks, start=1):
            try:
                json.loads(html.unescape(block).strip())
            except json.JSONDecodeError as exc:
                fail(errors, f"{path.name}: invalid JSON-LD block {index}: {exc.msg}")


def audit_quarantine(errors: list[str]) -> None:
    blog_index = (ROOT / "blog.html").read_text(encoding="utf-8")
    sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
    for name in sorted(QUARANTINED):
        text = (ROOT / name).read_text(encoding="utf-8")
        if not re.search(r'name=["\']robots["\'][^>]*content=["\']noindex,\s*follow["\']', text, re.I):
            fail(errors, f"{name}: quarantine page must use noindex,follow")
        if "pagead2.googlesyndication.com" in text or "wanyutong-ads.js" in text:
            fail(errors, f"{name}: quarantine page must not load AdSense")
        if name in blog_index:
            fail(errors, f"blog.html: quarantined page is still listed: {name}")
        if name in sitemap:
            fail(errors, f"sitemap.xml: quarantined page is still listed: {name}")
        if "內容重新整理中" not in text:
            fail(errors, f"{name}: missing visible maintenance explanation")


def audit_pillars(errors: list[str]) -> None:
    for name, required_source in PILLARS.items():
        text = (ROOT / name).read_text(encoding="utf-8")
        checks = {
            "Article structured data": '"@type":"Article"' in text.replace(" ", "") or '"@type": "Article"' in text,
            "2026-08-31 review date": "2026-08-31" in text,
            "verification section": "article-verification" in text,
            "known limitation": "已知限制" in text,
            "editorial policy link": "editorial.html" in text,
            f"required source/term {required_source}": required_source in text,
        }
        for label, passed in checks.items():
            if not passed:
                fail(errors, f"{name}: missing {label}")
        if "lang-content" in text:
            fail(errors, f"{name}: legacy duplicated bilingual template remains")


def audit_banned_claims(errors: list[str], html_files: list[Path]) -> None:
    corpus = "\n".join(path.read_text(encoding="utf-8") for path in html_files)
    banned = {
        "unsupported 0.3-second claim": ("0.3秒", "'0.3s'", '"0.3s"'),
        "legacy repeated CTA": ("先把最常誤會的句子翻清楚",),
        "misleading mock Official badge": ('class="bot-chat-official">Official<',),
        "outdated limited-language quota": ("每天 50 次免費翻譯（限英／日／韓）", "每日 50 次免費翻譯（限英／日／韓）"),
        "stale named competitor labels": (
            "'vs.col.echonora': 'Echonora'",
            "'vs.col.t2go':     'T2GO'",
            "'vs.col.ligo':     'Ligo'",
        ),
        "stale competitor price or quota claims": (
            "USD (More Expensive)",
            "20/day Free",
            "5,000-char quota",
            "美金（較貴）",
            "每日20次",
            "5,000字元額度",
        ),
        "stale language-count comparison": (
            "Currently 8 langs",
            "目前8種",
            "Up to 5 langs",
            "最多5種",
        ),
        "unsupported blanket comparison": (
            "✕ Usually no management-risk reminder",
            "✕ Requires App Switch",
            "✕ Requires Another App",
            "✕ 通常不會提醒管理風險",
            "支援多，但需離開 LINE 操作",
        ),
    }
    for label, needles in banned.items():
        for needle in needles:
            if needle in corpus:
                fail(errors, f"site: {label} remains ({needle})")


def main() -> int:
    errors: list[str] = []
    html_files = sorted(ROOT.glob("*.html"))
    audit_structure(errors, html_files)
    audit_internal_links(errors, html_files)
    audit_local_assets(errors, html_files)
    audit_json_ld(errors, html_files)
    audit_quarantine(errors)
    audit_pillars(errors)
    audit_banned_claims(errors, html_files)

    if errors:
        print(f"FAIL: {len(errors)} content audit issue(s)")
        for item in errors:
            print(f"- {item}")
        return 1

    print(
        "PASS: content structure, internal links, quarantine rules, pillar evidence, "
        "and banned-claim checks all passed"
    )
    print(f"Checked {len(html_files)} HTML files, {len(PILLARS)} pillar pages, and {len(QUARANTINED)} quarantine pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
