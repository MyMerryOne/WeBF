import unittest
from unittest.mock import patch

from evidence.signing import verify_detached_signature


class TestDetachedSignature(unittest.TestCase):
    def test_requires_payload_and_signature(self):
        result = verify_detached_signature(b"", b"signature", b"trust")
        self.assertFalse(result["verified"])

    def test_requires_trust_anchor(self):
        result = verify_detached_signature(b"payload", b"signature", b"")
        self.assertFalse(result["verified"])
        self.assertIn("trust anchor", result["error"])

    @patch("evidence.signing.subprocess.run")
    def test_reports_successful_external_verification(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "CMS Verification successful"
        run.return_value.stderr = ""

        result = verify_detached_signature(b"payload", b"signature", b"trust")

        self.assertTrue(result["verified"])
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["openssl", "cms", "-verify", "-binary", "-inform"])

    @patch("evidence.signing.subprocess.run")
    def test_reports_failed_external_verification(self, run):
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "verification failure"

        result = verify_detached_signature(b"payload", b"signature", b"trust")

        self.assertFalse(result["verified"])
        self.assertIn("verification failure", result["output"])


if __name__ == "__main__":
    unittest.main()
