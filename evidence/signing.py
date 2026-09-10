"""Verification adapter for externally produced detached CMS signatures."""
import subprocess
import tempfile
from typing import Any


def verify_detached_signature(
    payload: bytes,
    signature: bytes,
    trust_pem: bytes,
    untrusted_pem: bytes = b"",
    timeout: int = 30,
) -> dict[str, Any]:
    """Verify a DER-encoded detached CMS signature with OpenSSL.

    WeBF never handles signing keys. An external controlled signer produces the
    signature; this adapter verifies it against supplied trust material.
    """
    if not payload or not signature:
        return {"verified": False, "error": "payload and signature are required"}
    if not trust_pem:
        return {"verified": False, "error": "signature trust anchor is required"}

    try:
        with tempfile.TemporaryDirectory() as tmp:
            payload_path = f"{tmp}/payload.bin"
            signature_path = f"{tmp}/signature.der"
            trust_path = f"{tmp}/trust.pem"
            untrusted_path = f"{tmp}/untrusted.pem"
            with open(payload_path, "wb") as stream:
                stream.write(payload)
            with open(signature_path, "wb") as stream:
                stream.write(signature)
            with open(trust_path, "wb") as stream:
                stream.write(trust_pem)

            command = [
                "openssl", "cms", "-verify", "-binary", "-inform", "DER",
                "-in", signature_path, "-content", payload_path,
                "-CAfile", trust_path, "-out", "/dev/null",
            ]
            if untrusted_pem:
                with open(untrusted_path, "wb") as stream:
                    stream.write(untrusted_pem)
                command.extend(["-untrusted", untrusted_path])

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
            return {
                "verified": result.returncode == 0,
                "output": (result.stdout + result.stderr).strip()[-2000:],
            }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"verified": False, "error": f"signature verification failed: {exc}"}
