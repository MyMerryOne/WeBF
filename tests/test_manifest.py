"""Tests for packaging/manifest.py — stdlib + datetime only."""
import unittest
import json
import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from packaging.manifest import build_manifest, serialize_manifest


def _make_manifest(**overrides):
    """Return a manifest built with safe defaults."""
    utc = datetime.timezone.utc
    defaults = dict(
        url="https://example.com/page",
        operator="Test Operator",
        case_ref="CASE-001",
        notes="Unit test capture",
        jurisdiction_id="eu",
        start_time_utc=datetime.datetime(2026, 8, 21, 10, 0, 0, tzinfo=utc),
        end_time_utc=datetime.datetime(2026, 8, 21, 10, 1, 30, tzinfo=utc),
        http_result={
            "final_url": "https://example.com/page",
            "status_code": 200,
            "reason": "OK",
            "content_type": "text/html; charset=utf-8",
            "elapsed_ms": 342,
            "redirect_chain": [],
            "response_headers": {"Content-Type": "text/html"},
        },
        network_result={
            "hostname": "example.com",
            "dns": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": [], "TXT": []},
            "tls": {
                "subject": "CN=example.com",
                "issuer": "CN=DigiCert",
                "sha256_fingerprint": "aa:bb:cc",
                "not_valid_before": "2025-01-01T00:00:00",
                "not_valid_after": "2026-01-01T00:00:00",
            },
            "whois": {"parsed": {"registrar": "IANA"}, "raw": ""},
        },
        browser_result={
            "page_title": "Example Domain",
            "final_url": "https://example.com/page",
        },
        artifact_hashes={
            "capture/page.warc.gz": {
                "sha256": "a" * 64,
                "sha512": "b" * 128,
            }
        },
        tsa_url="https://freetsa.org/tsr",
        extra_operator_fields=None,
    )
    defaults.update(overrides)
    return build_manifest(**defaults)


class TestBuildManifest(unittest.TestCase):

    def test_top_level_keys_present(self):
        m = _make_manifest()
        for key in ("schema_version", "tool", "capture", "timing",
                    "operator", "jurisdiction", "tsa_url",
                    "network", "response_headers", "artifacts",
                    "primary_evidence", "hash_algorithms"):
            self.assertIn(key, m, f"Missing top-level key: {key}")

    def test_schema_version(self):
        self.assertEqual(_make_manifest()["schema_version"], "1.0")

    def test_tool_fields(self):
        m = _make_manifest()
        self.assertIn("name", m["tool"])
        self.assertIn("version", m["tool"])

    def test_capture_url(self):
        m = _make_manifest(url="https://example.com/page")
        self.assertEqual(m["capture"]["target_url"], "https://example.com/page")

    def test_capture_http_status(self):
        m = _make_manifest()
        self.assertEqual(m["capture"]["http_status"], 200)

    def test_timing_iso_format(self):
        m = _make_manifest()
        start = m["timing"]["capture_start_utc"]
        self.assertIn("2026-08-21", start)
        self.assertIn("10:00:00", start)

    def test_timing_timezone_utc(self):
        m = _make_manifest()
        self.assertEqual(m["timing"]["timezone"], "UTC")

    def test_operator_name(self):
        m = _make_manifest(operator="Paolo Romagnoli")
        self.assertEqual(m["operator"]["name"], "Paolo Romagnoli")

    def test_operator_case_ref(self):
        m = _make_manifest(case_ref="MYCASE-42")
        self.assertEqual(m["operator"]["case_reference"], "MYCASE-42")

    def test_operator_notes(self):
        m = _make_manifest(notes="Captured for exhibit A")
        self.assertEqual(m["operator"]["notes"], "Captured for exhibit A")

    def test_jurisdiction(self):
        m = _make_manifest(jurisdiction_id="it")
        self.assertEqual(m["jurisdiction"], "it")

    def test_tsa_url(self):
        m = _make_manifest(tsa_url="https://freetsa.org/tsr")
        self.assertEqual(m["tsa_url"], "https://freetsa.org/tsr")

    def test_network_hostname(self):
        m = _make_manifest()
        self.assertEqual(m["network"]["hostname"], "example.com")

    def test_network_dns_a_records(self):
        m = _make_manifest()
        self.assertEqual(m["network"]["dns"]["A"], ["93.184.216.34"])

    def test_network_tls_present(self):
        m = _make_manifest()
        self.assertIsNotNone(m["network"]["tls"])

    def test_artifact_hashes_preserved(self):
        m = _make_manifest()
        self.assertIn("capture/page.warc.gz", m["artifacts"])
        self.assertEqual(m["artifacts"]["capture/page.warc.gz"]["sha256"], "a" * 64)

    def test_primary_evidence_is_warc(self):
        m = _make_manifest()
        self.assertEqual(m["primary_evidence"], "capture/page.warc.gz")

    def test_hash_algorithms_include_sha256_and_sha512(self):
        m = _make_manifest()
        self.assertIn("sha256", m["hash_algorithms"])
        self.assertIn("sha512", m["hash_algorithms"])

    def test_extra_operator_fields_merged(self):
        m = _make_manifest(extra_operator_fields={
            "operator_role": "CTU",
            "operator_cf": "RMGPLA80A01H501Z",
        })
        self.assertEqual(m["operator"]["operator_role"], "CTU")
        self.assertEqual(m["operator"]["operator_cf"], "RMGPLA80A01H501Z")

    def test_browser_result_none_ok(self):
        m = _make_manifest(browser_result=None)
        self.assertEqual(m["capture"]["page_title"], "")

    def test_redirect_chain_empty(self):
        m = _make_manifest()
        self.assertEqual(m["capture"]["redirect_chain"], [])

    def test_redirect_chain_populated(self):
        http = {
            "final_url": "https://www.example.com/",
            "status_code": 200,
            "reason": "OK",
            "content_type": "text/html",
            "elapsed_ms": 500,
            "redirect_chain": [
                {"url": "http://example.com/", "status_code": 301},
            ],
            "response_headers": {},
        }
        m = _make_manifest(http_result=http)
        self.assertEqual(len(m["capture"]["redirect_chain"]), 1)


class TestSerializeManifest(unittest.TestCase):

    def test_returns_bytes(self):
        m = _make_manifest()
        result = serialize_manifest(m)
        self.assertIsInstance(result, bytes)

    def test_valid_json(self):
        m = _make_manifest()
        raw = serialize_manifest(m)
        parsed = json.loads(raw)
        self.assertIsInstance(parsed, dict)

    def test_round_trip(self):
        m = _make_manifest()
        raw = serialize_manifest(m)
        parsed = json.loads(raw)
        self.assertEqual(parsed["capture"]["target_url"], "https://example.com/page")
        self.assertEqual(parsed["operator"]["name"], "Test Operator")

    def test_utf8_encoding(self):
        m = _make_manifest(notes="Testemunho — página capturada. Česká republika.")
        raw = serialize_manifest(m)
        parsed = json.loads(raw.decode("utf-8"))
        self.assertIn("Česká", parsed["operator"]["notes"])

    def test_pretty_printed(self):
        m = _make_manifest()
        raw = serialize_manifest(m)
        # Should have newlines (pretty-printed)
        self.assertIn(b"\n", raw)


if __name__ == "__main__":
    unittest.main()
