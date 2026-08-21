"""SHA-256 and SHA-512 hashing for all captured artifacts."""
import hashlib
from typing import Any


def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def hash_artifacts(artifacts: dict[str, bytes]) -> dict[str, dict[str, str]]:
    """Return {filename: {sha256: ..., sha512: ...}} for each artifact."""
    return {name: hash_bytes(data) for name, data in artifacts.items()}
