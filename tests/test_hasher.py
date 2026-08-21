"""Tests for evidence/hasher.py — pure stdlib, no external deps."""
import unittest
import hashlib
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from evidence.hasher import hash_bytes, hash_artifacts


class TestHashBytes(unittest.TestCase):

    def test_known_sha256_empty(self):
        result = hash_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        self.assertEqual(result["sha256"], expected)

    def test_known_sha256_hello(self):
        result = hash_bytes(b"hello")
        self.assertEqual(
            result["sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_known_sha512_hello(self):
        result = hash_bytes(b"hello")
        self.assertEqual(
            result["sha512"],
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        )

    def test_both_keys_present(self):
        result = hash_bytes(b"data")
        self.assertIn("sha256", result)
        self.assertIn("sha512", result)

    def test_sha256_is_hex_string_64_chars(self):
        result = hash_bytes(b"anything")
        self.assertIsInstance(result["sha256"], str)
        self.assertEqual(len(result["sha256"]), 64)

    def test_sha512_is_hex_string_128_chars(self):
        result = hash_bytes(b"anything")
        self.assertIsInstance(result["sha512"], str)
        self.assertEqual(len(result["sha512"]), 128)

    def test_different_inputs_different_hashes(self):
        a = hash_bytes(b"aaa")
        b = hash_bytes(b"bbb")
        self.assertNotEqual(a["sha256"], b["sha256"])

    def test_deterministic(self):
        self.assertEqual(hash_bytes(b"test"), hash_bytes(b"test"))


class TestHashArtifacts(unittest.TestCase):

    def test_empty_dict(self):
        self.assertEqual(hash_artifacts({}), {})

    def test_single_artifact(self):
        result = hash_artifacts({"file.txt": b"hello"})
        self.assertIn("file.txt", result)
        self.assertIn("sha256", result["file.txt"])
        self.assertIn("sha512", result["file.txt"])

    def test_multiple_artifacts(self):
        artifacts = {
            "a.bin": b"aaa",
            "b.bin": b"bbb",
            "c.bin": b"ccc",
        }
        result = hash_artifacts(artifacts)
        self.assertEqual(set(result.keys()), set(artifacts.keys()))

    def test_hash_values_match_hash_bytes(self):
        data = b"forensic test data"
        result = hash_artifacts({"evidence.bin": data})
        expected = hash_bytes(data)
        self.assertEqual(result["evidence.bin"]["sha256"], expected["sha256"])
        self.assertEqual(result["evidence.bin"]["sha512"], expected["sha512"])

    def test_path_separator_preserved(self):
        result = hash_artifacts({"capture/page.warc.gz": b"warc"})
        self.assertIn("capture/page.warc.gz", result)


if __name__ == "__main__":
    unittest.main()
