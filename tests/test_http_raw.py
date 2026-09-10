import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).parents[1]))

from capture.http_raw import capture_http
from capture.url_policy import validate_public_url


class TestCaptureHttp(unittest.TestCase):

    def test_rejects_private_literal_target(self):
        with self.assertRaisesRegex(ValueError, "non-public capture address"):
            validate_public_url("https://127.0.0.1/")

    def test_rejects_credentials_in_target(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            validate_public_url("https://user:secret@example.test/")

    @patch("capture.http_raw.requests.Session")
    def test_tls_failure_fails_closed_without_insecure_retry(self, session_class):
        with patch("capture.http_raw.validate_public_url"):
            session = session_class.return_value
            session.get.side_effect = requests.exceptions.SSLError("certificate mismatch")

            with self.assertRaisesRegex(RuntimeError, "TLS certificate verification failed"):
                capture_http("https://example.test")

            session.get.assert_called_once_with(
                "https://example.test",
                timeout=30,
                allow_redirects=False,
                stream=True,
                verify=True,
            )

    @patch("capture.http_raw.validate_public_url")
    @patch("capture.http_raw.requests.Session")
    def test_redirect_is_validated_before_next_request(self, session_class, validate):
        session = session_class.return_value
        first = unittest.mock.Mock(
            is_redirect=True,
            headers={"Location": "https://private.example/"},
            url="https://example.test/",
            status_code=302,
            reason="Found",
        )
        session.get.return_value = first
        validate.side_effect = [None, ValueError("non-public capture address")]

        with self.assertRaisesRegex(ValueError, "non-public capture address"):
            capture_http("https://example.test")

        self.assertEqual(session.get.call_count, 1)


if __name__ == "__main__":
    unittest.main()