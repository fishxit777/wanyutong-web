"""Extract web copy and render WanyuTong's public pages in static locale folders."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment, Doctype, NavigableString, ProcessingInstruction, Tag


ORIGIN = 'https://wanyutong.tw'
SHARED_SCRIPT_REVISION = '20261122-static-site-locales-v2'
SHARED_SCRIPTS = {
    'assets/wanyutong-app.js',
    'assets/wanyutong-card.js',
    'assets/wanyutong-analytics.js',
}
SCRIPT_SOURCE = re.compile(
    r'''(?P<attribute><script\b[^>]*?\ssrc\s*=\s*)(?P<quote>["'])(?P<url>[^"']+)(?P=quote)''',
    re.IGNORECASE,
)
LOCALES = {
    'zh': ('zh-Hant', '繁體中文', '繁中', '語言'),
    'zh-Hans': ('zh-Hans', '简体中文', '简中', '语言'),
    'en': ('en', 'English', 'EN', 'Language'),
    'ja': ('ja', '日本語', '日本語', '言語'),
    'ko': ('ko', '한국어', '한국어', '언어'),
    'id': ('id', 'Bahasa Indonesia', 'ID', 'Bahasa'),
}
LOCALE_FOLDERS = {'zh-Hans': 'zh-cn'}
UNLOCALIZED = {'google3ba367f41a0000ba.html', 'blog-image-ocr-checklist.html'}
HIDDEN_ELEMENTS = {'script', 'style', 'template', 'svg', 'math'}
LANGUAGE_CONTROL_CLASSES = {'wyt-language', 'lang-toggle', 'language-switch', 'article-lang-switch'}
TEXT_ATTRIBUTES = {'alt', 'aria-label', 'aria-description', 'placeholder', 'title', 'data-label'}
META_FIELDS = {'description', 'keywords', 'og:title', 'og:description', 'og:image:alt',
               'twitter:title', 'twitter:description', 'twitter:image:alt'}
STRUCTURED_TEXT = {'headline', 'alternativeHeadline', 'description', 'articleSection', 'keywords',
                   'name', 'text'}
STRUCTURED_LINKS = {'url', '@id', 'mainEntityOfPage', 'item'}
COMMANDS = re.compile(
    r'[@＠](?:(?:語言設定|多語)(?: (?:繁體中文|簡體中文|中文|英文|日文|韓文|印尼文|越南文|泰文|菲律賓語)){1,8}'
    r'|恢復置頂提醒|群組狀態|支援語言|語言設定|新手教學|說明|選單|多語|語言|方案|到期|'
    r'秘書|祕書|客服|姓名|969wpxno|wanyutongtw)', re.I
)
TRANSLATABLE = re.compile(r'[A-Za-z\u3400-\u9FFF]')
PROTECTED_LABELS = {'LINE', 'LINE Bot', 'WanyuTong', '萬語通', 'OCR', 'AI', 'SOP', 'FAQ', 'Gmail',
                    'Google', 'Google Forms', 'DeepL', 'Excel', 'Web', 'LINE ID', 'QR Code',
                    'H.264', 'AAC', 'MP4', 'GitHub Pages', 'Showcase'}


@dataclass
class CopyNode:
    owner: Tag | NavigableString | dict
    field: str | None
    value: str
    english: str | None = None

    def set(self, value: str) -> None:
        if self.field is not None:
            self.owner[self.field] = value
        else:
            left = self.value[:len(self.value) - len(self.value.lstrip())]
            right = self.value[len(self.value.rstrip()):]
            self.owner.replace_with(NavigableString(left + value + right))


def normalize(value: str) -> str:
    return ' '.join(value.split())


def source_text(value: str) -> str:
    return BeautifulSoup(value, 'html.parser').get_text(' ', strip=True)


def can_translate(value: str) -> bool:
    if value in PROTECTED_LABELS or not TRANSLATABLE.search(value):
        return False
    if COMMANDS.fullmatch(value) or re.fullmatch(r'[\w.+-]+@[\w.-]+\.\w+', value):
        return False
    return not value.startswith(('https://', 'http://'))


def old_language_control(tag: Tag) -> bool:
    return bool(LANGUAGE_CONTROL_CLASSES.intersection(tag.get('class', ())))


def ignored(tag: Tag) -> bool:
    for node in (tag, *tag.parents):
        if node.name in HIDDEN_ELEMENTS or old_language_control(node):
            return True
    return False


def existing_english(node: NavigableString) -> str | None:
    parent = node.parent
    for anchor in (parent, *parent.parents):
        source, translation = anchor.get('data-zh'), anchor.get('data-en')
        if isinstance(source, str) and isinstance(translation, str):
            if normalize(source_text(source)) == normalize(str(node)):
                return normalize(source_text(translation))
    return None


def structured_data(soup: BeautifulSoup):
    for script in soup.find_all('script', type='application/ld+json'):
        if script.string:
            try:
                yield script, json.loads(script.string)
            except json.JSONDecodeError:
                # Keep invalid legacy blocks untouched instead of losing metadata.
                continue


def dictionaries(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from dictionaries(child)
    if isinstance(value, list):
        for child in value:
            yield from dictionaries(child)


def copy_nodes(soup: BeautifulSoup, structures):
    for text in soup.find_all(string=True):
        if isinstance(text, (Comment, Doctype, ProcessingInstruction)) or ignored(text.parent):
            continue
        value = str(text)
        if can_translate(normalize(value)):
            yield CopyNode(text, None, value, existing_english(text))
    for tag in soup.find_all(True):
        if ignored(tag):
            continue
        fields = TEXT_ATTRIBUTES.intersection(tag.attrs)
        if tag.name == 'meta' and (tag.get('name') or tag.get('property')) in META_FIELDS:
            fields.add('content')
        if tag.name == 'input' and tag.get('type') in ('button', 'submit', 'reset'):
            fields.add('value')
        for field in sorted(fields):
            value = tag.get(field)
            if isinstance(value, str) and can_translate(normalize(value)):
                yield CopyNode(tag, field, value)
    for _, structure in structures:
        for obj in dictionaries(structure):
            for field in sorted(STRUCTURED_TEXT.intersection(obj)):
                if isinstance(obj[field], str) and can_translate(normalize(obj[field])):
                    yield CopyNode(obj, field, obj[field])


def pages_at(root: Path) -> list[str]:
    return sorted(file.name for file in root.glob('*.html') if file.name not in UNLOCALIZED)


def read_page(root: Path, filename: str) -> BeautifulSoup:
    return BeautifulSoup((root / filename).read_text(encoding='utf-8-sig'), 'html.parser')


def json_write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def extract(root: Path, output: Path) -> dict:
    entries = defaultdict(lambda: {'pages': set(), 'english': set()})
    pages = pages_at(root)
    for filename in pages:
        soup = read_page(root, filename)
        for node in copy_nodes(soup, list(structured_data(soup))):
            value = normalize(node.value)
            entries[value]['pages'].add(filename)
            if node.english and node.english != value and commands_preserved(value, node.english):
                entries[value]['english'].add(node.english)
    strings = {}
    for value, data in sorted(entries.items()):
        strings[value] = {'pages': sorted(data['pages'])}
        if len(data['english']) == 1:
            strings[value]['english'] = next(iter(data['english']))
    catalog = {'pages': pages, 'strings': strings}
    json_write(output, catalog)
    print(f'Extracted {len(strings)} strings from {len(pages)} pages.')
    return catalog


def commands_preserved(source: str, translation: str) -> bool:
    required = {command.casefold() for command in COMMANDS.findall(source)}
    supplied = {command.casefold() for command in COMMANDS.findall(translation)}
    return required == supplied




def public_path(filename: str, locale: str) -> str:
    folder = '' if locale == 'zh' else LOCALE_FOLDERS.get(locale, locale) + '/'
    tail = '' if filename == 'index.html' else filename
    return '/' + folder + tail


def rewrite_url(value: str, locale: str, pages: set[str]) -> str:
    if not value or value.startswith(('#', '?')):
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme and parsed.scheme not in {'http', 'https'}:
        return value
    if parsed.netloc and parsed.hostname != 'wanyutong.tw':
        return value
    path = parsed.path
    cleaned = path.removeprefix('./').lstrip('/')
    prefix, separator, remainder = cleaned.partition('/')
    if separator and (prefix in LOCALES or prefix in LOCALE_FOLDERS.values()):
        cleaned = remainder
    if cleaned in ('', '.'):
        cleaned = 'index.html'
    if cleaned == 'blog-image-ocr-checklist.html':
        cleaned = 'blog-image-ocr-translation.html'
        parsed = parsed._replace(fragment=parsed.fragment or 'checklist')
    if cleaned in pages:
        return urlunsplit(parsed._replace(path=public_path(cleaned, locale)))
    if parsed.netloc:
        return value
    if cleaned.startswith(('assets/', 'scripts/')) or '/' not in cleaned and '.' in cleaned:
        return urlunsplit(parsed._replace(path='/' + cleaned))
    return value


def version_shared_script(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    path = parsed.path.removeprefix('./').lstrip('/')
    if parsed.scheme or parsed.netloc or path not in SHARED_SCRIPTS:
        return value
    return urlunsplit(parsed._replace(query=f'v={SHARED_SCRIPT_REVISION}'))


def rewrite_links(soup: BeautifulSoup, locale: str, pages: set[str]) -> None:
    for tag in soup.find_all(True):
        if old_language_control(tag) and 'wyt-language' in tag.get('class', []):
            continue
        for field in ('href', 'src', 'poster', 'action', 'cite', 'longdesc'):
            value = tag.get(field)
            if isinstance(value, str):
                rewritten = rewrite_url(value, locale, pages)
                tag[field] = version_shared_script(rewritten) if tag.name == 'script' and field == 'src' else rewritten
        srcset = tag.get('srcset')
        if isinstance(srcset, str) and not srcset.lstrip().startswith('data:'):
            candidates = []
            for candidate in srcset.split(','):
                parts = candidate.split()
                if parts:
                    parts[0] = rewrite_url(parts[0], locale, pages)
                    candidates.append(' '.join(parts))
            tag['srcset'] = ', '.join(candidates)
        if tag.name == 'meta' and tag.get('property') == 'og:url':
            tag['content'] = rewrite_url(tag.get('content', ''), locale, pages)


def add_language_control(soup: BeautifulSoup, filename: str, locale: str) -> None:
    html_lang, active_name, compact, label = LOCALES[locale]
    soup.html['data-wyt-static-locale'] = locale
    soup.html['lang'] = html_lang
    for established in soup.select('details.wyt-language'):
        established.decompose()
    roots = soup.select('.lang-toggle, .language-switch, .article-lang-switch')
    for group in roots:
        group['hidden'] = ''
        group['data-wyt-legacy-language'] = ''
    details = soup.new_tag('details', attrs={'class': 'wyt-language'})
    summary = soup.new_tag('summary', attrs={'aria-label': f'{label}: {active_name}',
                                             'data-compact': compact})
    name_display = soup.new_tag('span')
    name_display.string = active_name
    summary.append(name_display)
    details.append(summary)
    options = soup.new_tag('div', attrs={'class': 'wyt-language-options', 'aria-label': label})
    for option, (code, name, _, _) in LOCALES.items():
        anchor = soup.new_tag('a', href=public_path(filename, option), lang=code, hreflang=code)
        if option == locale:
            anchor['aria-current'] = 'page'
        anchor.string = name
        options.append(anchor)
    details.append(options)
    if roots:
        roots[0].insert_after(details)
    else:
        containers = ('.site-header .header-inner', '.site-header', '.topbar', 'nav:not(.toc)', 'body')
        anchor = next((result for selector in containers if (result := soup.select_one(selector))), None)
        if anchor is None:
            raise ValueError(f'{filename}: missing public header')
        anchor.append(details)


def add_locale_metadata(soup: BeautifulSoup, filename: str, locale: str, assets: dict[str, str]) -> None:
    for tag in soup.select('link[rel~=canonical], link[rel~=alternate][hreflang]'):
        tag.decompose()
    canonical = ORIGIN + public_path(filename, locale)
    soup.head.append(soup.new_tag('link', rel='canonical', href=canonical))
    for option, (code, *_) in LOCALES.items():
        soup.head.append(soup.new_tag('link', rel='alternate', hreflang=code,
                                      href=ORIGIN + public_path(filename, option)))
    soup.head.append(soup.new_tag('link', rel='alternate', hreflang='x-default',
                                  href=ORIGIN + public_path(filename, 'zh')))
    for meta in soup.select('meta[property="og:url"]'):
        meta['content'] = canonical
    for meta in soup.select('meta[property="og:locale"]'):
        meta['content'] = {'zh': 'zh_TW', 'zh-Hans': 'zh_CN', 'en': 'en_US', 'ja': 'ja_JP',
                           'ko': 'ko_KR', 'id': 'id_ID'}[locale]
    style_href = '/assets/wanyutong-locales.css'
    menu_src = '/assets/wanyutong-locale-menu.js'
    style = soup.select_one(f'link[href="{style_href}"]') or soup.new_tag(
        'link', rel='stylesheet', href=style_href)
    menu = soup.select_one(f'script[src="{menu_src}"]') or soup.new_tag(
        'script', src=menu_src, defer='')
    for url, tag in ((style_href, style), (menu_src, menu)):
        if not tag.parent:
            soup.head.append(tag)
        if url in assets:
            tag['integrity'] = assets[url]
            tag['crossorigin'] = 'anonymous'


def rewrite_structured_data(structures, locale: str, pages: set[str]) -> None:
    for tag, dataset in structures:
        for obj in dictionaries(dataset):
            if 'inLanguage' in obj:
                obj['inLanguage'] = LOCALES[locale][0]
            for field in STRUCTURED_LINKS.intersection(obj):
                original = obj[field]
                if isinstance(original, str) and original.startswith(ORIGIN + '/'):
                    if obj.get('@type') in ('Organization', 'Person', 'WebSite'):
                        continue
                    obj[field] = rewrite_url(original, locale, pages)
        # Keep script boundaries safe even when translations include markup characters.
        serialized = json.dumps(dataset, ensure_ascii=False).replace('<', '\\u003c')
        tag.string = serialized


def source_offset(lines: list[int], tag: Tag) -> int:
    return lines[tag.sourceline - 1] + tag.sourcepos


class ClosingTag(HTMLParser):
    def __init__(self, target: Tag) -> None:
        super().__init__()
        self.name = target.name
        self.start = (target.sourceline, target.sourcepos)
        self.end = None
        self.depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == self.name and self.end is None and (self.depth or self.getpos() == self.start):
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == self.name and self.depth:
            self.depth -= 1
            if not self.depth:
                self.end = self.getpos()


def root_page(source: Path, filename: str, assets: dict[str, str]) -> str:
    # Add the shared controls without reserializing any existing Chinese site HTML.
    raw = (source / filename).read_text(encoding='utf-8-sig')
    raw = SCRIPT_SOURCE.sub(
        lambda match: match['attribute'] + match['quote'] + version_shared_script(match['url']) + match['quote'],
        raw,
    )
    raw = re.sub(r'<details class="wyt-language">.*?</details>', '', raw, flags=re.S)
    raw = re.sub(r'<link\b(?=[^>]*\bhreflang=)[^>]*>', '', raw, flags=re.I)
    raw = re.sub(r'<link\b(?=[^>]*\bhref="/assets/wanyutong-locales\.css")[^>]*>', '', raw, flags=re.I)
    raw = re.sub(r'<script\b(?=[^>]*\bsrc="/assets/wanyutong-locale-menu\.js")[^>]*></script>', '', raw, flags=re.I)
    soup = BeautifulSoup(raw, 'html.parser')
    groups = soup.select('.lang-toggle, .language-switch, .article-lang-switch')
    has_canonical = soup.select_one('link[rel~=canonical]') is not None
    lines = [0, *(match.end() for match in re.finditer('\n', raw))]
    add_language_control(soup, filename, 'zh')
    control = soup.select_one('.wyt-language')
    if groups:
        insertion = source_offset(lines, groups[0])
    else:
        finder = ClosingTag(control.parent)
        finder.feed(raw)
        if finder.end is None:
            raise ValueError(f'{filename}: no closing tag for the language selector container')
        line, column = finder.end
        insertion = lines[line - 1] + column
    replacements = [(insertion, insertion, str(control))]
    for group in groups:
        start = source_offset(lines, group)
        stop = raw.index('>', start)
        if 'data-wyt-legacy-language' not in raw[start:stop]:
            replacements.append((stop, stop, ' hidden="" data-wyt-legacy-language=""'))
    metadata = BeautifulSoup('<head></head>', 'html.parser')
    add_locale_metadata(metadata, filename, 'zh', assets)
    if has_canonical:
        metadata.select_one('link[rel~=canonical]').decompose()
    head_end = re.search(r'</head\s*>', raw, flags=re.I).start()
    replacements.append((head_end, head_end, metadata.head.decode_contents()))
    if not re.search(r'<html\b[^>]*\bdata-wyt-static-locale=', raw, flags=re.I):
        html = re.search(r'<html\b', raw, flags=re.I)
        replacements.append((html.end(), html.end(), ' data-wyt-static-locale="zh"'))
    for start, stop, content in sorted(replacements, reverse=True):
        raw = raw[:start] + content + raw[stop:]
    return raw


def render_page(source: Path, filename: str, locale: str, pages: set[str],
                translations: dict[str, str], assets: dict[str, str]) -> str:
    if locale == 'zh':
        return root_page(source, filename, assets)
    soup = read_page(source, filename)
    structures = list(structured_data(soup))
    for node in copy_nodes(soup, structures):
        key = normalize(node.value)
        translated = translations.get(key, '')
        if not translated and locale == 'en' and node.english and commands_preserved(key, node.english):
            translated = node.english
        if translated:
            node.set(translated)
    rewrite_links(soup, locale, pages)
    for track in soup.select('#complete-guide video[data-guide-captions] track[kind="subtitles"]'):
        track.attrs.pop('default', None)
        if track.get('srclang') == LOCALES[locale][0]:
            track['default'] = ''
    rewrite_structured_data(structures, locale, pages)
    add_language_control(soup, filename, locale)
    add_locale_metadata(soup, filename, locale, assets)
    return soup.decode(formatter='minimal')


def dictionary_from(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict) or any(not isinstance(v, str) for v in data.values()):
        raise ValueError(f'{path.name}: need a JSON object with source keys and text values')
    return {normalize(key): normalize(value) for key, value in data.items()}


def required_translation_coverage(source: Path, pages: set[str], locale: str, translations: dict[str, str]):
    missing = set()
    invalid = set()
    for filename in sorted(pages):
        soup = read_page(source, filename)
        for node in copy_nodes(soup, list(structured_data(soup))):
            key = normalize(node.value)
            translated = translations.get(key, '')
            if not translated and locale == 'en' and node.english and commands_preserved(key, node.english):
                translated = node.english
            if not translated:
                missing.add(key)
            elif not commands_preserved(key, translated):
                invalid.add(key)
    return missing, invalid


def build(root: Path, output: Path, maps: Path, locales: list[str], include_root: bool,
          rendered_root: Path | None, allow_incomplete: bool) -> None:
    import base64
    import hashlib

    pages = set(pages_at(root))
    source = rendered_root or root
    if set(pages_at(source)) != pages:
        raise ValueError('Rendered source routes differ from source site')
    assets = {}
    for name in ('assets/wanyutong-locales.css', 'assets/wanyutong-locale-menu.js'):
        path = root / name
        if path.is_file():
            # GitHub Pages serves these text assets with LF endings.
            contents = path.read_bytes().replace(b"\r\n", b"\n")
            checksum = hashlib.sha384(contents).digest()
            assets['/' + name] = 'sha384-' + base64.b64encode(checksum).decode('ascii')
    rendered = {}
    for locale in dict.fromkeys(locales):
        translations = dictionary_from(maps / f'{locale}.json')
        missing, invalid = required_translation_coverage(source, pages, locale, translations)
        if invalid or missing and not allow_incomplete:
            examples = '; '.join(repr(item) for item in sorted(missing | invalid)[:8])
            raise ValueError(f'{locale}: {len(missing)} missing; {len(invalid)} command mismatches. {examples}')
        if missing:
            print(f'{locale}: draft has {len(missing)} untranslated strings', file=sys.stderr)
        rendered[locale] = translations
    if include_root:
        rendered['zh'] = {}
    for locale, translations in rendered.items():
        destination = output if locale == 'zh' else output / LOCALE_FOLDERS.get(locale, locale)
        destination.mkdir(parents=True, exist_ok=True)
        for filename in sorted(pages):
            base = root if locale == 'zh' else source
            page = render_page(base, filename, locale, pages, translations, assets)
            (destination / filename).write_text(page, encoding='utf-8')
    print(f'Rendered {len(pages)} pages for {", ".join(rendered)}.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    extraction = commands.add_parser('extract', help='Write the source string catalog')
    generation = commands.add_parser('build', help='Generate localized pages from translation maps')
    for command in (extraction, generation):
        command.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
        command.add_argument('--output', type=Path, required=True)
    generation.add_argument('--maps', type=Path, required=True)
    generation.add_argument('--locale', action='append', choices=tuple(LOCALES)[1:])
    generation.add_argument('--include-root', action='store_true')
    generation.add_argument('--rendered-root', type=Path)
    generation.add_argument('--allow-incomplete', action='store_true',
                            help='Only for previews; leave missing copy in its source language')
    args = parser.parse_args()
    if args.command == 'extract':
        extract(args.root, args.output)
    else:
        build(args.root, args.output, args.maps, args.locale or list(LOCALES)[1:],
              args.include_root, args.rendered_root, args.allow_incomplete)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(str(error))
