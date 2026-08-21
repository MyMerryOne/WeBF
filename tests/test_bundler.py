"""Tests for packaging/bundler.py — stdlib only (zipfile, io, json)."""
import unittest
import zipfile
import json
import io
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from packaging.bundler import (
    assemble_package,
    _build_verify_script,
    _build_verify_script_windows,
    _build_verification_readme,
)


def _default_package(**overrides) -> bytes:
    defaults = dict(
        manifest_bytes=b'{"schema_version":"1.0","tool":{"name":"WeBF","version":"1.0.0"}}',
        manifest_hashes={"sha256": "a" * 64, "sha512": "b" * 128},
        report_html=b"<html><body>Report</body></html>",
        report_pdf=b"%PDF-1.4\n%Test",
        warc_bytes=b"WARC/1.1\r\n",
        screenshot_full=b"\x89PNG\r\n\x1a\nFULL",
        screenshot_vp=b"\x89PNG\r\n\x1a\nVP",
        rendered_html=b"<html>rendered</html>",
        page_pdf=b"%PDF-1.4\npage",
        http_raw_bytes=b"HTTP/1.1 200 OK\r\n\r\n",
        network_result={
            "dns": {"A": ["1.2.3.4"]},
            "whois": {"raw": "WHOIS data"},
            "tls": {"subject": "CN=example.com"},
        },
        timestamp_result={
            "tsq_bytes": b"\x30\x00",
            "tsr_bytes": b"\x30\x05\x02\x01\x00\x05\x00",
            "tsa_url": "https://freetsa.org/tsr",
            "data_hash_hex": "c" * 64,
            "parsed": {"status": "granted", "gen_time": "20260821120000Z"},
        },
        artifact_hashes={
            "capture/page.warc.gz": {"sha256": "d" * 64, "sha512": "e" * 128},
            "capture/screenshot_full.png": {"sha256": "f" * 64, "sha512": "g" * 128},
        },
    )
    defaults.update(overrides)
    return assemble_package(**defaults)


class TestAssemblePackage(unittest.TestCase):

    def test_returns_bytes(self):
        result = _default_package()
        self.assertIsInstance(result, bytes)

    def test_output_is_valid_zip(self):
        data = _default_package()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            self.assertIsNotNone(zf.namelist())

    def _names(self, **overrides) -> list[str]:
        data = _default_package(**overrides)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            return zf.namelist()

    def test_manifest_json_present(self):
        self.assertIn("manifest.json", self._names())

    def test_manifest_sha256_present(self):
        self.assertIn("manifest.sha256", self._names())

    def test_report_html_present(self):
        self.assertIn("report/forensic_report.html", self._names())

    def test_report_pdf_present(self):
        self.assertIn("report/forensic_report.pdf", self._names())

    def test_warc_present(self):
        self.assertIn("capture/page.warc.gz", self._names())

    def test_screenshot_full_present(self):
        self.assertIn("capture/screenshot_full.png", self._names())

    def test_screenshot_viewport_present(self):
        self.assertIn("capture/screenshot_viewport.png", self._names())

    def test_rendered_html_present(self):
        self.assertIn("capture/page.html", self._names())

    def test_page_pdf_present(self):
        self.assertIn("capture/page.pdf", self._names())

    def test_http_response_raw_present(self):
        self.assertIn("capture/http_response_raw.bin", self._names())

    def test_dns_json_present(self):
        self.assertIn("network/dns.json", self._names())

    def test_whois_txt_present(self):
        self.assertIn("network/whois.txt", self._names())

    def test_tls_certificate_json_present(self):
        self.assertIn("network/tls_certificate.json", self._names())

    def test_timestamp_request_present(self):
        self.assertIn("timestamp/request.tsq", self._names())

    def test_timestamp_response_present(self):
        self.assertIn("timestamp/response.tsr", self._names())

    def test_timestamp_info_json_present(self):
        self.assertIn("timestamp/timestamp_info.json", self._names())

    def test_verify_sh_present(self):
        self.assertIn("timestamp/verify.sh", self._names())

    def test_verify_ps1_present(self):
        self.assertIn("timestamp/verify.ps1", self._names())

    def test_verification_md_present(self):
        self.assertIn("VERIFICATION.md", self._names())

    def test_manifest_sha256_file_content(self):
        data = _default_package()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            sha256_stored = zf.read("manifest.sha256").decode()
        self.assertEqual(sha256_stored, "a" * 64)

    def test_manifest_json_content(self):
        data = _default_package()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            raw = zf.read("manifest.json")
        parsed = json.loads(raw)
        self.assertEqual(parsed["schema_version"], "1.0")

    def test_dns_json_is_valid_json(self):
        data = _default_package()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            raw = zf.read("network/dns.json")
        parsed = json.loads(raw)
        self.assertIn("A", parsed)

    def test_timestamp_info_json_has_tsa_url(self):
        data = _default_package()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            raw = zf.read("timestamp/timestamp_info.json")
        info = json.loads(raw)
        self.assertEqual(info["tsa_url"], "https://freetsa.org/tsr")

    def test_empty_screenshot_not_included(self):
        names = self._names(screenshot_full=b"", screenshot_vp=b"")
        self.assertNotIn("capture/screenshot_full.png", names)
        self.assertNotIn("capture/screenshot_viewport.png", names)

    def test_empty_rendered_html_not_included(self):
        names = self._names(rendered_html=b"")
        self.assertNotIn("capture/page.html", names)

    def test_empty_page_pdf_not_included(self):
        names = self._names(page_pdf=b"")
        self.assertNotIn("capture/page.pdf", names)


class TestBuildVerifyScript(unittest.TestCase):

    def test_contains_tsa_url(self):
        script = _build_verify_script({"tsa_url": "https://freetsa.org/tsr"})
        self.assertIn("https://freetsa.org/tsr", script)

    def test_contains_openssl_ts_verify(self):
        script = _build_verify_script({"tsa_url": ""})
        self.assertIn("openssl ts -verify", script)

    def test_references_request_tsq(self):
        script = _build_verify_script({"tsa_url": ""})
        self.assertIn("request.tsq", script)

    def test_references_response_tsr(self):
        script = _build_verify_script({"tsa_url": ""})
        self.assertIn("response.tsr", script)

    def test_contains_shebang(self):
        script = _build_verify_script({"tsa_url": ""})
        self.assertTrue(script.startswith("#!/usr/bin/env bash"))


class TestBuildVerifyScriptWindows(unittest.TestCase):

    def test_contains_tsa_url(self):
        script = _build_verify_script_windows({"tsa_url": "https://freetsa.org/tsr"})
        self.assertIn("https://freetsa.org/tsr", script)

    def test_contains_openssl_ts_verify(self):
        script = _build_verify_script_windows({"tsa_url": ""})
        self.assertIn("openssl ts -verify", script)

    def test_contains_powershell_variable(self):
        script = _build_verify_script_windows({"tsa_url": ""})
        self.assertIn("$ScriptDir", script)

    def test_contains_lastexitcode_check(self):
        script = _build_verify_script_windows({"tsa_url": ""})
        self.assertIn("LASTEXITCODE", script)


class TestBuildVerificationReadme(unittest.TestCase):

    def test_contains_manifest_hash(self):
        readme = _build_verification_readme(
            {"sha256": "aabbccdd" * 8, "sha512": "x" * 128},
            {},
        )
        self.assertIn("aabbccdd" * 8, readme)

    def test_contains_artifact_hashes(self):
        hashes = {
            "capture/page.warc.gz": {"sha256": "1" * 64, "sha512": "2" * 128},
        }
        readme = _build_verification_readme({"sha256": "a" * 64, "sha512": "b" * 128}, hashes)
        self.assertIn("capture/page.warc.gz", readme)
        self.assertIn("1" * 64, readme)

    def test_contains_sha256sum_instruction(self):
        readme = _build_verification_readme({"sha256": "a" * 64, "sha512": "b" * 128}, {})
        self.assertIn("sha256sum", readme)

    def test_contains_powershell_instruction(self):
        readme = _build_verification_readme({"sha256": "a" * 64, "sha512": "b" * 128}, {})
        self.assertIn("Get-FileHash", readme)

    def test_multiple_artifacts_all_listed(self):
        hashes = {
            f"file{i}.bin": {"sha256": str(i) * 64, "sha512": str(i) * 128}
            for i in range(5)
        }
        readme = _build_verification_readme({"sha256": "a" * 64, "sha512": "b" * 128}, hashes)
        for i in range(5):
            self.assertIn(f"file{i}.bin", readme)


if __name__ == "__main__":
    unittest.main()
