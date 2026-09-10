"""Playwright-based browser capture: screenshot, PDF, rendered HTML, legal modals."""
import os
from typing import Any
from urllib.parse import urlparse

from capture.url_policy import validate_public_url


TOOL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WeBF/1.0"
)


def _isolated_egress_proxy() -> dict[str, str] | None:
    """Return the configured egress proxy, failing closed when required."""
    proxy = os.environ.get("WEBF_BROWSER_PROXY", "").strip()
    required = os.environ.get("WEBF_REQUIRE_ISOLATED_EGRESS", "") == "1"
    if required and not proxy:
        raise RuntimeError(
            "isolated browser egress is required; set WEBF_BROWSER_PROXY"
        )
    return {"server": proxy} if proxy else None

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
    "Only necessary",
    "Decline optional cookies", "Decline optional", "Allow only essential cookies",
    "Accetta solo necessari", "Odmítnout", "Ablehnen",
]


def _guard_navigation(route, request) -> None:
    """Abort browser HTTP(S) requests outside the public-web scope."""
    scheme = urlparse(request.url).scheme.lower()
    if scheme in {"http", "https"}:
        try:
            validate_public_url(request.url)
        except ValueError:
            route.abort(error_code="blockedbyclient")
            return
    route.continue_()


def _wait_and_capture(page, url: str) -> dict[str, Any]:
    validate_public_url(url)
    page.route("**/*", _guard_navigation)
    page.set_extra_http_headers({"User-Agent": TOOL_UA})
    console_errors: list[str] = []
    page_errors: list[str] = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    try:
        response = page.goto(url, wait_until="networkidle", timeout=60_000)
    finally:
        page.unroute("**/*", _guard_navigation)
    validate_public_url(page.url)
    _dismiss_translation_prompt(page)
    _dismiss_cookie_banner(page)
    _dismiss_logged_out_prompt(page)

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

    return {
        "final_url": final_url,
        "http_status": status_code,
        "page_title": page_title,
        "rendered_html": rendered_html,
        "screenshot_full_png": screenshot_full,
        "screenshot_viewport_png": screenshot_vp,
        "pdf_bytes": pdf_bytes,
        "console_errors": console_errors,
        "page_errors": page_errors,
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
                page.wait_for_timeout(1_500)
                return
        except Exception:
            continue
    # Fall back to text matching
    for text in _COOKIE_REJECT_TEXTS:
        try:
            btn = page.locator("button").filter(has_text=text).first
            btn.wait_for(state="visible", timeout=3_000)
            btn.click()
            page.wait_for_timeout(1_500)
            if btn.is_visible():
                btn.evaluate("element => element.click()")
                page.wait_for_timeout(1_500)
            return
        except Exception:
            continue


def _dismiss_logged_out_prompt(page) -> None:
    """Close Instagram's logged-out prompt so the public profile remains visible."""
    try:
        if "instagram.com" not in page.url:
            return
        page.wait_for_timeout(1_000)
        for _ in range(2):
            close_button = page.locator(
                '[role="dialog"]:visible button[aria-label="Close"]'
            ).first
            if close_button.count() and close_button.is_visible(timeout=800):
                close_button.click()
                page.wait_for_timeout(500)
                continue
            page.keyboard.press("Escape")
            page.wait_for_timeout(500)
        return
    except Exception:
        pass


def _dismiss_translation_prompt(page) -> None:
    """Close Airbnb's translation explainer when it obscures the listing."""
    try:
        if "airbnb.com" not in page.url:
            return
        close_button = page.locator('button[aria-label="Close"]').last
        if close_button.count() and close_button.is_visible(timeout=800):
            close_button.click()
            page.wait_for_timeout(500)
    except Exception:
        pass


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


def _pdf_modal_on_fresh_page(context, url: str, link: dict) -> bytes:
    """Open a fresh page, navigate to *url*, click the legal modal trigger,
    expand all overflow/max-height constraints, hide the background, then
    print to PDF so the full modal text is captured across pages.

    Uses a separate page so DOM manipulation does not affect the shared
    page that is still needed for subsequent modal captures.
    """
    _JS_EXPAND_MODAL = """(el) => {
        const expand = (node) => {
            const s = node.style;
            s.overflow = 'visible';
            s.overflowY = 'visible';
            s.overflowX = 'visible';
            s.maxHeight = 'none';
            s.height = 'auto';
            for (const c of node.children) expand(c);
        };
        expand(el);
        // Reposition out of fixed/absolute stacking so it flows in the document
        el.style.position = 'relative';
        el.style.transform = 'none';
        el.style.top = 'auto';
        el.style.left = 'auto';
        el.style.right = 'auto';
        el.style.bottom = 'auto';
        el.style.margin = '0 auto';
        el.style.width = '100%';
        el.style.maxWidth = '900px';
        el.style.boxShadow = 'none';
        el.style.borderRadius = '0';
        // Hide everything else so only the modal content is printed
        for (const child of document.body.children) {
            if (!child.contains(el) && child !== el)
                child.style.display = 'none';
        }
        document.body.style.overflow = 'visible';
        document.body.style.background = 'white';
        document.body.style.margin = '0';
        document.body.style.padding = '0';
    }"""

    pdf_page = context.new_page()
    try:
        validate_public_url(url)
        pdf_page.route("**/*", _guard_navigation)
        pdf_page.goto(url, wait_until="networkidle", timeout=60_000)
        _dismiss_cookie_banner(pdf_page)

        trigger = _find_trigger(pdf_page, link)
        if trigger:
            trigger.scroll_into_view_if_needed()
            trigger.click()
            modal = _find_modal(pdf_page)
            pdf_page.wait_for_timeout(600)
            if modal:
                try:
                    modal.evaluate(_JS_EXPAND_MODAL)
                    pdf_page.wait_for_timeout(200)
                except Exception:
                    pass

        return pdf_page.pdf(
            format="A4",
            print_background=True,
            margin={"top": "15mm", "bottom": "15mm", "left": "15mm", "right": "15mm"},
        )
    finally:
        pdf_page.unroute("**/*", _guard_navigation)
        pdf_page.close()


def _capture_one_modal(page, link: dict, url: str = "", context=None) -> dict[str, Any]:
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

    # PDF — use a fresh page so DOM manipulation (overflow removal, background
    # hiding) does not corrupt the shared page used for subsequent modals.
    if context and url:
        pdf_bytes: bytes = _pdf_modal_on_fresh_page(context, url, link)
    else:
        pdf_bytes = page.pdf(
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
        launch_options: dict[str, Any] = {"headless": True}
        proxy = _isolated_egress_proxy()
        if proxy:
            launch_options["proxy"] = proxy
        browser = pw.chromium.launch(**launch_options)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=TOOL_UA,
            ignore_https_errors=False,
        )
        page = context.new_page()
        try:
            validate_public_url(url)
            page.route("**/*", _guard_navigation)
            page.goto(url, wait_until="networkidle", timeout=60_000)
            _dismiss_cookie_banner(page)

            for link in embedded:
                slug = link["slug"]
                try:
                    results[slug] = _capture_one_modal(page, link, url=url, context=context)
                except Exception as exc:
                    results[slug] = {"error": str(exc)}
        finally:
            page.unroute("**/*", _guard_navigation)
            context.close()
            browser.close()

    return results


def capture_browser(url: str) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        launch_options: dict[str, Any] = {"headless": True}
        proxy = _isolated_egress_proxy()
        if proxy:
            launch_options["proxy"] = proxy
        browser = pw.chromium.launch(**launch_options)
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
