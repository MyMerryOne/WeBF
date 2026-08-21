"""Playwright-based browser capture: screenshot, PDF, rendered HTML, legal modals."""
from typing import Any


TOOL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WeBF-ForensicCapture/1.0"
)

# Selectors tried in order to locate a visible modal after clicking a legal link
_MODAL_SELECTORS = [
    '[role="dialog"]:visible',
    '[aria-modal="true"]:visible',
    '.modal:visible',
    '.overlay:visible',
    '.popup:visible',
    '.lightbox:visible',
]

# Text patterns for "accept necessary only" cookie buttons (multilingual)
_COOKIE_REJECT_TEXTS = [
    "Solo necessari", "Rifiuta", "Reject all", "Reject", "Necessary only",
    "Accetta solo necessari", "Odmítnout", "Ablehnen",
]


def _wait_and_capture(page, url: str) -> dict[str, Any]:
    page.set_extra_http_headers({"User-Agent": TOOL_UA})
    response = page.goto(url, wait_until="networkidle", timeout=60_000)

    status_code = response.status if response else None
    final_url = page.url

    rendered_html: bytes = page.content().encode("utf-8")

    screenshot_full: bytes = page.screenshot(full_page=True, type="png")
    screenshot_vp: bytes = page.screenshot(full_page=False, type="png")

    page.emulate_media(media="print")
    page.evaluate("window.scrollTo(0, 0)")
    pdf_bytes: bytes = page.pdf(
        format="A4",
        print_background=True,
        margin={"top": "15mm", "bottom": "15mm", "left": "15mm", "right": "15mm"},
    )
    page.emulate_media(media="screen")

    page_title: str = page.title()

    console_errors: list[str] = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

    return {
        "final_url": final_url,
        "http_status": status_code,
        "page_title": page_title,
        "rendered_html": rendered_html,
        "screenshot_full_png": screenshot_full,
        "screenshot_viewport_png": screenshot_vp,
        "pdf_bytes": pdf_bytes,
    }


def _dismiss_cookie_banner(page) -> None:
    """Attempt to dismiss a cookie consent banner by clicking 'necessary only'."""
    # Try known id-based buttons first (fast, precise)
    id_selectors = [
        "button#btnCookieReject", "button#cookieReject", "button#rejectAll",
        "button[id*='reject']", "button[id*='necessary']", "button[id*='decline']",
    ]
    for sel in id_selectors:
        try:
            btn = page.locator(sel).first
            if btn.count() and btn.is_visible(timeout=800):
                btn.click()
                page.wait_for_timeout(400)
                return
        except Exception:
            continue
    # Fall back to text matching
    for text in _COOKIE_REJECT_TEXTS:
        try:
            btn = page.get_by_role("button", name=text, exact=False).first
            if btn.count() and btn.is_visible(timeout=600):
                btn.click()
                page.wait_for_timeout(400)
                return
        except Exception:
            continue


def _find_trigger(page, link: dict):
    """Return a Playwright Locator for the anchor that opens this legal section."""
    # 1. data-policy attribute (most precise — JS modal pattern)
    dp = link.get("template_id", "").replace("tpl-", "") if link.get("template_id") else None
    if dp:
        loc = page.locator(f'a[data-policy="{dp}"]').first
        if loc.count():
            return loc
    # 2. href="#fragment"
    fid = link.get("fragment_id")
    if fid:
        loc = page.locator(f'a[href="#{fid}"]').first
        if loc.count():
            return loc
    # 3. Exact link text
    label = link["label"]
    loc = page.get_by_role("link", name=label, exact=True).first
    if loc.count():
        return loc
    # 4. Partial link text
    loc = page.get_by_role("link", name=label, exact=False).first
    if loc.count():
        return loc
    return None


def _find_modal(page):
    """Return a Locator for the modal that just became visible, or None."""
    for sel in _MODAL_SELECTORS:
        try:
            page.wait_for_selector(sel, state="visible", timeout=3_000)
            loc = page.locator(sel).first
            if loc.count():
                return loc
        except Exception:
            continue
    return None


def _close_modal(page) -> None:
    """Attempt to close an open modal via common close-button patterns."""
    close_selectors = [
        'button[aria-label="Chiudi"]', 'button[aria-label="Close"]',
        'button[aria-label="Zavřít"]', 'button[aria-label="Schließen"]',
        "button[id*='close']", "button[id*='Close']",
        ".modal-close", ".close", "[data-dismiss='modal']",
    ]
    for sel in close_selectors:
        try:
            btn = page.locator(sel).first
            if btn.count() and btn.is_visible(timeout=600):
                btn.click()
                page.wait_for_timeout(400)
                return
        except Exception:
            continue
    # Fallback: press Escape
    try:
        page.keyboard.press("Escape")
        page.wait_for_timeout(400)
    except Exception:
        pass


def _capture_one_modal(page, link: dict) -> dict[str, Any]:
    """Click the trigger for *link*, capture the resulting modal, close it."""
    trigger = _find_trigger(page, link)
    if trigger is None:
        raise RuntimeError(f"No clickable element found for '{link['label']}'")

    trigger.scroll_into_view_if_needed()
    trigger.click()

    modal = _find_modal(page)
    # Allow CSS transition to complete
    page.wait_for_timeout(600)

    # Screenshot — prefer the modal element; fall back to viewport
    if modal:
        try:
            screenshot_png: bytes = modal.screenshot(type="png")
        except Exception:
            screenshot_png = page.screenshot(full_page=False, type="png")
    else:
        screenshot_png = page.screenshot(full_page=False, type="png")

    # Rendered HTML — prefer modal inner HTML; fall back to full page
    if modal:
        try:
            rendered_html: bytes = modal.inner_html().encode("utf-8")
        except Exception:
            rendered_html = page.content().encode("utf-8")
    else:
        rendered_html = page.content().encode("utf-8")

    # PDF of the page with the modal open (shows the modal in context)
    pdf_bytes: bytes = page.pdf(
        format="A4",
        print_background=True,
        margin={"top": "15mm", "bottom": "15mm", "left": "15mm", "right": "15mm"},
    )

    _close_modal(page)

    return {
        "screenshot_png": screenshot_png,
        "rendered_html": rendered_html,
        "pdf_bytes": pdf_bytes,
    }


def capture_legal_modals(url: str, legal_links: list[dict]) -> dict[str, dict[str, Any]]:
    """Open a browser, navigate to *url*, click each embedded legal link, and
    capture a screenshot, rendered HTML, and PDF of the resulting modal.

    Returns a dict keyed by ``slug``.  Each value is either
    ``{screenshot_png, rendered_html, pdf_bytes}`` or ``{"error": str}``.
    Only links with ``embedded=True`` are processed; others are skipped.
    """
    from playwright.sync_api import sync_playwright

    embedded = [lk for lk in legal_links if lk.get("embedded")]
    if not embedded:
        return {}

    results: dict[str, dict[str, Any]] = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=TOOL_UA,
            ignore_https_errors=False,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=60_000)
            _dismiss_cookie_banner(page)

            for link in embedded:
                slug = link["slug"]
                try:
                    results[slug] = _capture_one_modal(page, link)
                except Exception as exc:
                    results[slug] = {"error": str(exc)}
        finally:
            context.close()
            browser.close()

    return results


def capture_browser(url: str) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=TOOL_UA,
            ignore_https_errors=False,
        )
        page = context.new_page()
        try:
            result = _wait_and_capture(page, url)
        finally:
            context.close()
            browser.close()
    return result
