"""Pure-stdlib DER encoding helpers for RFC 3161 TimeStampReq construction.

No external dependencies — safe to import and test without pip installs.
"""
import hashlib
import os


# DER OID bytes for digest algorithms
SHA256_OID_DER = bytes([
    0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
])
SHA512_OID_DER = bytes([
    0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
])


def der_length(n: int) -> bytes:
    """Encode a DER length field."""
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def der_seq(*parts: bytes) -> bytes:
    """Wrap parts in a DER SEQUENCE (tag 0x30)."""
    content = b"".join(parts)
    return b"\x30" + der_length(len(content)) + content


def der_integer(value: int) -> bytes:
    """Encode a non-negative integer as DER INTEGER (tag 0x02)."""
    raw = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + der_length(len(raw)) + raw


def der_octet_string(data: bytes) -> bytes:
    """Encode bytes as DER OCTET STRING (tag 0x04)."""
    return b"\x04" + der_length(len(data)) + data


def der_boolean_true() -> bytes:
    """Return DER encoding of BOOLEAN TRUE."""
    return b"\x01\x01\xff"


def build_timestamp_request(data: bytes, use_sha512: bool = False) -> tuple[bytes, bytes]:
    """Build a DER-encoded RFC 3161 TimeStampReq.

    Returns (tsq_bytes, digest) where digest is the hash sent to the TSA.
    """
    if use_sha512:
        digest = hashlib.sha512(data).digest()
        oid_der = SHA512_OID_DER
    else:
        digest = hashlib.sha256(data).digest()
        oid_der = SHA256_OID_DER

    alg_id = der_seq(oid_der, b"\x05\x00")
    msg_imprint = der_seq(alg_id, der_octet_string(digest))
    nonce_int = int.from_bytes(os.urandom(8), "big")
    nonce = der_integer(nonce_int)

    ts_req = der_seq(
        der_integer(1),
        msg_imprint,
        nonce,
        der_boolean_true(),
    )
    return ts_req, digest
