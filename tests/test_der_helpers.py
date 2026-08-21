"""Tests for evidence/der_helpers.py — pure stdlib DER encoding for RFC 3161."""
import unittest
import hashlib
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from evidence.der_helpers import (
    der_length, der_seq, der_integer, der_octet_string,
    der_boolean_true, build_timestamp_request,
    SHA256_OID_DER, SHA512_OID_DER,
)


class TestDerLength(unittest.TestCase):

    def test_zero(self):
        self.assertEqual(der_length(0), b"\x00")

    def test_one(self):
        self.assertEqual(der_length(1), b"\x01")

    def test_127_short_form(self):
        self.assertEqual(der_length(127), b"\x7f")

    def test_128_long_form_one_byte(self):
        # 0x81 means "one length byte follows"
        self.assertEqual(der_length(128), b"\x81\x80")

    def test_255_long_form(self):
        self.assertEqual(der_length(255), b"\x81\xff")

    def test_256_long_form_two_bytes(self):
        # 0x82 means "two length bytes follow"
        self.assertEqual(der_length(256), b"\x82\x01\x00")

    def test_1000(self):
        self.assertEqual(der_length(1000), b"\x82\x03\xe8")


class TestDerInteger(unittest.TestCase):

    def test_zero(self):
        self.assertEqual(der_integer(0), b"\x02\x01\x00")

    def test_one(self):
        self.assertEqual(der_integer(1), b"\x02\x01\x01")

    def test_127(self):
        self.assertEqual(der_integer(127), b"\x02\x01\x7f")

    def test_128_requires_leading_zero(self):
        # 0x80 has MSB set — DER requires a leading 0x00 to keep it positive
        encoded = der_integer(128)
        self.assertEqual(encoded[0:1], b"\x02")   # INTEGER tag
        self.assertEqual(encoded[1], 2)            # length = 2 bytes
        self.assertEqual(encoded[2:4], b"\x00\x80")

    def test_255_requires_leading_zero(self):
        encoded = der_integer(255)
        self.assertEqual(encoded[1], 2)
        self.assertEqual(encoded[2:4], b"\x00\xff")

    def test_256(self):
        encoded = der_integer(256)
        self.assertEqual(encoded[0:1], b"\x02")
        self.assertEqual(encoded[2:4], b"\x01\x00")

    def test_large_nonce(self):
        # Simulate an 8-byte random nonce
        nonce = 0x0102030405060708
        encoded = der_integer(nonce)
        self.assertEqual(encoded[0:1], b"\x02")
        self.assertGreaterEqual(len(encoded), 2)


class TestDerOctetString(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(der_octet_string(b""), b"\x04\x00")

    def test_two_bytes(self):
        self.assertEqual(der_octet_string(b"AB"), b"\x04\x02AB")

    def test_sha256_digest_length(self):
        digest = hashlib.sha256(b"test").digest()
        encoded = der_octet_string(digest)
        self.assertEqual(encoded[0:1], b"\x04")
        self.assertEqual(encoded[1], 32)
        self.assertEqual(encoded[2:], digest)


class TestDerBooleanTrue(unittest.TestCase):

    def test_value(self):
        self.assertEqual(der_boolean_true(), b"\x01\x01\xff")


class TestDerSeq(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(der_seq(), b"\x30\x00")

    def test_single_byte(self):
        self.assertEqual(der_seq(b"\x01"), b"\x30\x01\x01")

    def test_two_parts(self):
        result = der_seq(b"AA", b"BB")
        self.assertEqual(result, b"\x30\x04AABB")

    def test_nested(self):
        inner = der_seq(b"\xff")
        outer = der_seq(inner)
        # outer = 30 03 30 01 ff
        self.assertEqual(outer[0:1], b"\x30")
        self.assertEqual(outer[2:3], b"\x30")

    def test_content_length_short_form(self):
        # 50+50=100 bytes — still < 128, so uses short-form DER length (1 byte: 0x64)
        a = b"X" * 50
        b = b"Y" * 50
        result = der_seq(a, b)
        self.assertEqual(result[0:1], b"\x30")
        self.assertEqual(result[1:2], bytes([100]))  # short form: 0x64

    def test_content_length_long_form(self):
        # 75+75=150 bytes — > 127, so uses long-form DER length (0x81 0x96)
        a = b"X" * 75
        b = b"Y" * 75
        result = der_seq(a, b)
        self.assertEqual(result[0:1], b"\x30")
        self.assertEqual(result[1:3], b"\x81\x96")  # long form: one-byte length = 150


class TestOidConstants(unittest.TestCase):

    def test_sha256_oid_tag_and_length(self):
        # 06 09 = OID tag, 9 bytes content
        self.assertEqual(SHA256_OID_DER[0], 0x06)
        self.assertEqual(SHA256_OID_DER[1], 0x09)
        self.assertEqual(len(SHA256_OID_DER), 11)

    def test_sha512_oid_tag_and_length(self):
        self.assertEqual(SHA512_OID_DER[0], 0x06)
        self.assertEqual(SHA512_OID_DER[1], 0x09)
        self.assertEqual(len(SHA512_OID_DER), 11)

    def test_sha256_and_sha512_oids_differ(self):
        self.assertNotEqual(SHA256_OID_DER, SHA512_OID_DER)


class TestBuildTimestampRequest(unittest.TestCase):

    def test_returns_tuple(self):
        result = build_timestamp_request(b"manifest data")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_tsq_is_bytes(self):
        tsq, digest = build_timestamp_request(b"data")
        self.assertIsInstance(tsq, bytes)
        self.assertIsInstance(digest, bytes)

    def test_tsq_starts_with_sequence_tag(self):
        tsq, _ = build_timestamp_request(b"data")
        self.assertEqual(tsq[0:1], b"\x30")

    def test_digest_is_sha256_of_input(self):
        data = b"test manifest"
        tsq, digest = build_timestamp_request(data)
        self.assertEqual(digest, hashlib.sha256(data).digest())
        self.assertEqual(len(digest), 32)

    def test_digest_is_sha512_when_requested(self):
        data = b"test manifest"
        tsq, digest = build_timestamp_request(data, use_sha512=True)
        self.assertEqual(digest, hashlib.sha512(data).digest())
        self.assertEqual(len(digest), 64)

    def test_sha512_tsq_is_larger(self):
        data = b"test"
        tsq256, _ = build_timestamp_request(data, use_sha512=False)
        tsq512, _ = build_timestamp_request(data, use_sha512=True)
        self.assertGreater(len(tsq512), len(tsq256))

    def test_nonce_randomised_between_calls(self):
        # Two requests for the same data should have different nonces
        tsq1, _ = build_timestamp_request(b"same data")
        tsq2, _ = build_timestamp_request(b"same data")
        # Not guaranteed to differ but astronomically likely with 8 random bytes
        self.assertNotEqual(tsq1, tsq2)

    def test_tsq_contains_sha256_oid(self):
        tsq, _ = build_timestamp_request(b"data")
        # The SHA-256 OID content bytes: 60 86 48 01 65 03 04 02 01
        oid_content = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        self.assertIn(oid_content, tsq)


if __name__ == "__main__":
    unittest.main()
