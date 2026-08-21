"""Playwright-based browser capture: screenshot, PDF, rendered HTML."""
from typing import Any


TOOL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WeBF-ForensicCapture/1.0"
)


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
