"""Render the Jinja2 HTML forensic report and convert to PDF via Playwright."""
import pathlib
import tempfile
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = pathlib.Path(__file__).parent.parent / "templates"


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_html_report(
    manifest: dict[str, Any],
    timestamp_info: dict[str, Any],
    jurisdiction_profile: dict[str, Any],
    extra_operator_fields: dict[str, str] | None = None,
) -> bytes:
    env = _get_env()
    template_name = jurisdiction_profile.get("report_template", "report_eu.html.j2")
    try:
        template = env.get_template(template_name)
    except Exception:
        template = env.get_template("report_eu.html.j2")

    html = template.render(
        manifest=manifest,
        timestamp=timestamp_info,
        profile=jurisdiction_profile,
        extra_fields=extra_operator_fields or {},
    )
    return html.encode("utf-8")


def render_pdf_report(html_bytes: bytes) -> bytes:
    """Use Playwright to print the HTML report as PDF (A4)."""
    from playwright.sync_api import sync_playwright
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="wb") as f:
        f.write(html_bytes)
        tmp_path = f.name

    tmp_file_url = pathlib.Path(tmp_path).as_uri()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(tmp_file_url, wait_until="networkidle")
        pdf_bytes = page.pdf(
            format="A4",
            print_background=True,
            margin={"top": "20mm", "bottom": "20mm", "left": "20mm", "right": "20mm"},
        )
        browser.close()

    pathlib.Path(tmp_path).unlink(missing_ok=True)
    return pdf_bytes
