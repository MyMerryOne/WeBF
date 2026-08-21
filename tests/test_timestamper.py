"""Tests for evidence/timestamper.py — requires requests (installed).

parse_timestamp_response requires pyasn1 (may not be installed); those tests
are skipped gracefully if the library is absent.  send_timestamp_request and
the full request_timestamp flow are tested with unittest.mock to avoid any
real network calls.
"""
import unittest
import hashlib
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pyasn1  # noqa: F401 — required; install with: pip install pyasn1 pyasn1-modules
PYASN1_AVAILABLE = True


class TestSendTimestampRequest(unittest.TestCase):

    def _make_mock_response(
        self,
        status_code: int = 200,
        content: bytes = b"\x30\x00",
        content_type: str = "application/timestamp-reply",
    ) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.content = content
        resp.text = content.decode("latin-1", errors="replace")
        resp.headers = {"Content-Type": content_type}
        return resp

    def test_returns_tsr_bytes_on_success(self):
        from evidence.timestamper import send_timestamp_request
        fake_tsr = b"\x30\x82\x01\xff" + b"\x00" * 20
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response(content=fake_tsr)
            result = send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr")
        self.assertEqual(result, fake_tsr)

    def test_sends_correct_content_type_header(self):
        from evidence.timestamper import send_timestamp_request
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response()
            send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr")
        _, kwargs = mock_post.call_args
        headers = kwargs.get("headers", {})
        self.assertEqual(headers.get("Content-Type"), "application/timestamp-query")

    def test_posts_to_correct_url(self):
        from evidence.timestamper import send_timestamp_request
        tsa_url = "https://freetsa.org/tsr"
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response()
            send_timestamp_request(b"\x30\x00", tsa_url)
        args, _ = mock_post.call_args
        self.assertEqual(args[0], tsa_url)

    def test_passes_tsq_as_data(self):
        from evidence.timestamper import send_timestamp_request
        tsq = b"\x30\x10" + b"\x01" * 16
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response()
            send_timestamp_request(tsq, "https://freetsa.org/tsr")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs.get("data"), tsq)

    def test_raises_on_non_200(self):
        from evidence.timestamper import send_timestamp_request
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response(status_code=400)
            with self.assertRaises(RuntimeError) as ctx:
                send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr")
        self.assertIn("400", str(ctx.exception))

    def test_raises_on_wrong_content_type(self):
        from evidence.timestamper import send_timestamp_request
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response(
                content_type="text/html"
            )
            with self.assertRaises(RuntimeError) as ctx:
                send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr")
        self.assertIn("Content-Type", str(ctx.exception))

    def test_accepts_octet_stream_content_type(self):
        from evidence.timestamper import send_timestamp_request
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response(
                content_type="application/octet-stream"
            )
            result = send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr")
        self.assertIsInstance(result, bytes)

    def test_timeout_passed_to_requests(self):
        from evidence.timestamper import send_timestamp_request
        with patch("evidence.timestamper.requests.post") as mock_post:
            mock_post.return_value = self._make_mock_response()
            send_timestamp_request(b"\x30\x00", "https://freetsa.org/tsr", timeout=15)
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs.get("timeout"), 15)


class TestRequestTimestamp(unittest.TestCase):
    """Integration test of request_timestamp using mocked TSA."""

    def _fake_tsr(self) -> bytes:
        # Minimal syntactically valid-ish TSR bytes for mock
        return b"\x30\x05\x02\x01\x00\x05\x00"

    def test_returns_expected_keys(self):
        from evidence.timestamper import request_timestamp
        with patch("evidence.timestamper.send_timestamp_request") as mock_send:
            with patch("evidence.timestamper.parse_timestamp_response") as mock_parse:
                mock_send.return_value = self._fake_tsr()
                mock_parse.return_value = {"status": "granted", "gen_time": "20260821120000Z"}
                result = request_timestamp(b"manifest", "https://freetsa.org/tsr")

        self.assertIn("tsq_bytes", result)
        self.assertIn("tsr_bytes", result)
        self.assertIn("data_hash_hex", result)
        self.assertIn("tsa_url", result)
        self.assertIn("parsed", result)

    def test_data_hash_hex_is_sha256(self):
        from evidence.timestamper import request_timestamp
        manifest = b"manifest content"
        with patch("evidence.timestamper.send_timestamp_request") as mock_send:
            with patch("evidence.timestamper.parse_timestamp_response") as mock_parse:
                mock_send.return_value = self._fake_tsr()
                mock_parse.return_value = {"status": "granted"}
                result = request_timestamp(manifest, "https://freetsa.org/tsr")

        expected_hash = hashlib.sha256(manifest).hexdigest()
        self.assertEqual(result["data_hash_hex"], expected_hash)

    def test_tsa_url_preserved(self):
        from evidence.timestamper import request_timestamp
        tsa = "https://freetsa.org/tsr"
        with patch("evidence.timestamper.send_timestamp_request") as mock_send:
            with patch("evidence.timestamper.parse_timestamp_response") as mock_parse:
                mock_send.return_value = self._fake_tsr()
                mock_parse.return_value = {"status": "granted"}
                result = request_timestamp(b"data", tsa)
        self.assertEqual(result["tsa_url"], tsa)

    def test_tsq_bytes_is_non_empty_der(self):
        from evidence.timestamper import request_timestamp
        with patch("evidence.timestamper.send_timestamp_request") as mock_send:
            with patch("evidence.timestamper.parse_timestamp_response") as mock_parse:
                mock_send.return_value = self._fake_tsr()
                mock_parse.return_value = {"status": "granted"}
                result = request_timestamp(b"data", "https://freetsa.org/tsr")
        tsq = result["tsq_bytes"]
        self.assertIsInstance(tsq, bytes)
        self.assertGreater(len(tsq), 10)
        self.assertEqual(tsq[0:1], b"\x30")  # DER SEQUENCE tag

    def test_tsr_bytes_stored(self):
        from evidence.timestamper import request_timestamp
        fake_tsr = b"\x30\xff" + b"\x00" * 10
        with patch("evidence.timestamper.send_timestamp_request") as mock_send:
            with patch("evidence.timestamper.parse_timestamp_response") as mock_parse:
                mock_send.return_value = fake_tsr
                mock_parse.return_value = {"status": "granted"}
                result = request_timestamp(b"data", "https://freetsa.org/tsr")
        self.assertEqual(result["tsr_bytes"], fake_tsr)


@unittest.skipUnless(PYASN1_AVAILABLE, "pyasn1 not installed — skipping parse tests")
class TestParseTimestampResponse(unittest.TestCase):

    def test_parse_error_returns_error_dict(self):
        from evidence.timestamper import parse_timestamp_response
        result = parse_timestamp_response(b"\x00\x00")
        self.assertIn("status", result)
        self.assertEqual(result["status"], "parse_error")

    def test_empty_bytes_returns_parse_error(self):
        from evidence.timestamper import parse_timestamp_response
        result = parse_timestamp_response(b"")
        self.assertEqual(result["status"], "parse_error")


if __name__ == "__main__":
    unittest.main()
