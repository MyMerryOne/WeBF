"""Detect legal sub-page links (Privacy Policy, Cookie Policy, T&C, etc.) from HTML."""
import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from typing import Any


_KEYWORDS = [
    # EN
    "privacy", "cookie", "terms", "conditions", "disclaimer",
    "legal notice", "legal information", "imprint", "gdpr",
    # IT
    "informativa", "termini", "condizioni", "note legali",
    "avviso legale", "trattamento",
    # CZ
    "soukrom", "osobn", "podmínk", "zásad", "právn",
    # DE (common on .eu sites)
    "datenschutz", "impressum",
]

_HREF_PATTERNS = [
    "/privacy", "/cookie", "/terms", "/legal", "/imprint",
    "/disclaimer", "/datenschutz", "/gdpr", "/informativa",
    "/condizioni", "/note-legali", "/avviso", "/soukromi",
    "/zasady", "/podmínky",
]


def _normalise(text: str) -> str:
    """Lower-case, strip accents for comparison (keeps é → e etc)."""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _is_legal(anchor_text: str, href: str) -> bool:
    norm_text = _normalise(anchor_text)
    norm_href = href.lower()
    for kw in _KEYWORDS:
        if _normalise(kw) in norm_text:
            return True
    for pat in _HREF_PATTERNS:
        if pat in norm_href:
            return True
    return False


def _make_slug(label: str) -> str:
    slug = _normalise(label)
    slug = re.sub(r"[^a-z0-9]+", "_", slug).strip("_")
    return slug[:30] or "legal_page"


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        # (href, anchor_text, data_policy_or_None)
        self._triples: list[tuple[str, str, str | None]] = []
        self._current_href: str | None = None
        self._current_policy: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            attr_map = dict(attrs)
            self._current_href = attr_map.get("href") or ""
            self._current_policy = attr_map.get("data-policy")
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            text = " ".join(self._current_text).strip()
            self._triples.append((self._current_href, text, self._current_policy))
            self._current_href = None
            self._current_policy = None
            self._current_text = []

    @property
    def pairs(self) -> list[tuple[str, str]]:
        return [(h, t) for h, t, _ in self._triples]

    @property
    def triples(self) -> list[tuple[str, str, str | None]]:
        return self._triples


def find_legal_links(
    html_bytes: bytes,
    base_url: str,
    max_links: int = 10,
) -> list[dict[str, Any]]:
    """Return legal sub-page candidates found in *html_bytes*.

    Each result is::

        {"label": str, "slug": str, "url": str, "embedded": bool}

    ``embedded=True`` means the legal content is served from the same page
    (href was ``#`` or a bare fragment) — the content is already captured in
    the main WARC record.  ``embedded=False`` means a distinct URL exists and
    should be fetched separately.

    Only same-origin URLs are considered; external domains are skipped.
    Deduplication is by resolved URL for non-embedded links; embedded links
    with distinct labels are kept as separate entries (different sections of
    the same page).
    """
    if not html_bytes:
        return []

    html_text = html_bytes.decode("utf-8", errors="replace")
    collector = _LinkCollector()
    try:
        collector.feed(html_text)
    except Exception:
        pass

    base_parsed = urlparse(base_url)
    base_netloc = base_parsed.netloc.lower()
    # Canonical form of the base page (no fragment)
    base_clean = base_parsed._replace(fragment="").geturl()

    seen_urls: set[str] = set()
    seen_slugs: dict[str, int] = {}
    # Track embedded labels to avoid duplicate "Privacy Policy" entries
    seen_embedded_slugs: set[str] = set()
    results: list[dict[str, Any]] = []

    for href, anchor_text, data_policy in collector.triples:
        href = href.strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
            continue
        if not _is_legal(anchor_text, href):
            continue

        # Detect embedded (same-page) links: href is "#" or "#fragment"
        is_embedded = href == "#" or (href.startswith("#") and len(href) > 1)
        # Also treat as embedded if the resolved URL equals the base page
        resolved = urljoin(base_url, href)
        parsed = urlparse(resolved)

        if not is_embedded and parsed.netloc.lower() != base_netloc:
            continue  # external domain

        label = anchor_text.strip() or href

        if is_embedded or parsed._replace(fragment="").geturl() == base_clean:
            # Legal content is embedded on the main page
            slug = _make_slug(label)
            if slug in seen_embedded_slugs:
                continue
            seen_embedded_slugs.add(slug)
            if slug in seen_slugs:
                seen_slugs[slug] += 1
                slug = f"{slug}_{seen_slugs[slug]}"
            else:
                seen_slugs[slug] = 1
            # Carry hints for content extraction:
            # data-policy="termini" → template id "tpl-termini"
            # href="#section-id"    → element id "section-id"
            template_id = f"tpl-{data_policy}" if data_policy else None
            fragment_id = href.lstrip("#") if href.startswith("#") and len(href) > 1 else None
            results.append({
                "label": label,
                "slug": slug,
                "url": base_clean,
                "embedded": True,
                "template_id": template_id,
                "fragment_id": fragment_id,
            })
        else:
            clean_url = parsed._replace(fragment="").geturl()
            if clean_url in seen_urls:
                continue
            seen_urls.add(clean_url)
            slug = _make_slug(label)
            if slug in seen_slugs:
                seen_slugs[slug] += 1
                slug = f"{slug}_{seen_slugs[slug]}"
            else:
                seen_slugs[slug] = 1
            results.append({"label": label, "slug": slug, "url": clean_url, "embedded": False})

        if len(results) >= max_links:
            break

    return results


# ── Embedded section extraction ───────────────────────────────────────────────


def _strip_tags(html_fragment: str) -> str:
    """Remove HTML tags, decode entities, and normalise whitespace."""
    text = re.sub(r"<(script|style)\b[^>]*>.*?</(script|style)>", "", html_fragment,
                  flags=re.DOTALL | re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</(p|div|li|tr|h[1-6]|section|article)>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    # Basic HTML entity decoding without importing html module
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">") \
               .replace("&nbsp;", " ").replace("&#39;", "'").replace("&quot;", '"')
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_block_by_id(html: str, element_id: str) -> str:
    """Return the inner HTML of the first element with the given id attribute."""
    m = re.search(
        rf'<(\w+)\b[^>]*\bid=["\x27]{re.escape(element_id)}["\x27][^>]*>',
        html, re.I,
    )
    if not m:
        return ""
    tag = m.group(1).lower()
    start = m.start()
    open_re = re.compile(rf"<{re.escape(tag)}\b", re.I)
    close_re = re.compile(rf"</{re.escape(tag)}\s*>", re.I)
    depth = 1
    i = m.end()
    while i < len(html) and depth > 0:
        nxt_open = open_re.search(html, i)
        nxt_close = close_re.search(html, i)
        if nxt_close is None:
            return html[start:]
        if nxt_open and nxt_open.start() < nxt_close.start():
            depth += 1
            i = nxt_open.end()
        else:
            depth -= 1
            i = nxt_close.end()
    return html[start:i]


def extract_embedded_section(html_bytes: bytes, link: dict[str, Any]) -> tuple[str, str]:
    """Extract the content of an embedded legal section from *html_bytes*.

    Tries three strategies in order:

    1. ``<template id="tpl-{data-policy}">`` — used by JS-modal patterns where
       the link carries a ``data-policy`` attribute.
    2. Element with ``id="{fragment_id}"`` — used when the href is ``#section-id``.
    3. Nearest block element containing a heading matching the label text.

    Returns ``(plain_text, html_fragment)``.  Both are empty strings if the
    section cannot be located.
    """
    html = html_bytes.decode("utf-8", errors="replace")

    # Strategy 1: <template id="tpl-..."> (JS modal pattern with data-policy)
    template_id = link.get("template_id")
    if template_id:
        m = re.search(
            rf'<template\b[^>]*\bid=["\x27]{re.escape(template_id)}["\x27][^>]*>(.*?)</template>',
            html, re.DOTALL | re.I,
        )
        if m:
            fragment = m.group(1).strip()
            return _strip_tags(fragment), fragment

    # Strategy 2: element with id matching the href fragment
    fragment_id = link.get("fragment_id")
    if fragment_id:
        block = _extract_block_by_id(html, fragment_id)
        if block:
            return _strip_tags(block), block

    # Strategy 3: nearest block element enclosing a heading matching the label
    label = link.get("label", "")
    norm_label = _normalise(label)
    heading_re = re.compile(r"<h[1-6]\b[^>]*>(.*?)</h[1-6]>", re.DOTALL | re.I)
    match_pos = -1
    for hm in heading_re.finditer(html):
        heading_text = re.sub(r"<[^>]+>", "", hm.group(1))
        if norm_label in _normalise(heading_text):
            match_pos = hm.start()
            break
    if match_pos == -1:
        # Last resort: plain-text substring search
        idx = html.lower().find(label.lower())
        if idx == -1:
            return "", ""
        match_pos = idx

    # Walk backward to nearest block-level opening tag
    block_open_re = re.compile(r"<(div|section|article|dialog|aside)\b", re.I)
    preceding_matches = list(block_open_re.finditer(html[:match_pos]))
    if not preceding_matches:
        return "", ""
    bm = preceding_matches[-1]
    tag_m = re.match(r"<(\w+)", html[bm.start():], re.I)
    if not tag_m:
        return "", ""
    tag = tag_m.group(1).lower()
    open_re = re.compile(rf"<{re.escape(tag)}\b", re.I)
    close_re = re.compile(rf"</{re.escape(tag)}\s*>", re.I)
    depth = 1
    i = bm.start() + len(tag_m.group(0))
    while i < len(html) and depth > 0:
        nxt_open = open_re.search(html, i)
        nxt_close = close_re.search(html, i)
        if nxt_close is None:
            i = len(html)
            break
        if nxt_open and nxt_open.start() < nxt_close.start():
            depth += 1
            i = nxt_open.end()
        else:
            depth -= 1
            i = nxt_close.end()
    block = html[bm.start():i]
    return _strip_tags(block), block
