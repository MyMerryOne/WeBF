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
        self._pairs: list[tuple[str, str]] = []  # (href, anchor_text)
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._current_href = dict(attrs).get("href") or ""
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            text = " ".join(self._current_text).strip()
            self._pairs.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    @property
    def pairs(self) -> list[tuple[str, str]]:
        return self._pairs


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

    for href, anchor_text in collector.pairs:
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
            results.append({"label": label, "slug": slug, "url": base_clean, "embedded": True})
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
