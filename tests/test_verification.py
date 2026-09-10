import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile

from click.testing import CliRunner

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from webf import _package_hash_errors, _package_inventory, _unsafe_package_members, cli


class TestPackageInventory(unittest.TestCase):

    def test_reports_missing_and_unexpected_members(self):
        manifest = {
            "artifacts": {"capture/page.warc.gz": {"sha256": "a", "sha512": "b"}}
        }
        missing, unexpected = _package_inventory(
            manifest,
            ["manifest.json", "manifest.sha256", "capture/page.warc.gz", "extra.txt"],
        )

        self.assertIn("report/capture_report.html", missing)
        self.assertIn("extra.txt", unexpected)

    def test_accepts_generated_legal_index(self):
        manifest = {
            "artifacts": {"capture/legal/privacy/page.html": {"sha256": "a", "sha512": "b"}}
        }
        missing, unexpected = _package_inventory(
            manifest,
            [
                "manifest.json",
                "manifest.sha256",
                "capture/legal/privacy/page.html",
                "capture/legal/legal_index.json",
                "report/capture_report.html",
                "report/capture_report.pdf",
                "network/dns.json",
                "network/whois.txt",
                "network/tls_certificate.json",
                "timestamp/request.tsq",
                "timestamp/response.tsr",
                "timestamp/timestamp_info.json",
                "timestamp/verify.sh",
                "timestamp/verify.ps1",
                "VERIFICATION.md",
            ],
        )

        self.assertNotIn("capture/legal/legal_index.json", missing)
        self.assertNotIn("capture/legal/legal_index.json", unexpected)

    def test_detects_unsafe_member_paths(self):
        unsafe = _unsafe_package_members(["capture/page.warc.gz", "../outside", "/absolute"])

        self.assertEqual(unsafe, {"../outside", "/absolute"})

    def test_uses_declared_package_members(self):
        manifest = {
            "package_members": ["manifest.json", "manifest.sha256", "declared.bin"],
            "artifacts": {},
        }
        missing, unexpected = _package_inventory(
            manifest,
            ["manifest.json", "manifest.sha256", "other.bin"],
        )
        self.assertEqual(missing, {"declared.bin"})
        self.assertEqual(unexpected, {"other.bin"})

    def test_package_hash_index_detects_member_tampering(self):
        member_data = b"original"
        index = {
            "payload.bin": {
                "sha256": hashlib.sha256(member_data).hexdigest(),
                "sha512": hashlib.sha512(member_data).hexdigest(),
            }
        }
        index_bytes = json.dumps(index).encode()
        with tempfile.TemporaryDirectory() as directory:
            package = pathlib.Path(directory) / "package-hashes.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("payload.bin", b"tampered")
                archive.writestr("package_hashes.json", index_bytes)
                archive.writestr("package_hashes.sha256", hashlib.sha256(index_bytes).hexdigest())
            with zipfile.ZipFile(package, "r") as archive:
                errors = _package_hash_errors(archive, archive.namelist())

        self.assertIn("package hash SHA-256 mismatch: payload.bin", errors)


class TestVerifyCommand(unittest.TestCase):

    def _write_package(self, path: pathlib.Path, artifact_sha512: str) -> None:
        artifact = b"primary evidence"
        manifest = {
            "artifacts": {
                "capture/page.warc.gz": {
                    "sha256": hashlib.sha256(artifact).hexdigest(),
                    "sha512": artifact_sha512,
                }
            }
        }
        manifest_bytes = json.dumps(manifest).encode()
        names = {
            "manifest.json": manifest_bytes,
            "manifest.sha256": hashlib.sha256(manifest_bytes).hexdigest().encode(),
            "capture/page.warc.gz": artifact,
            "report/capture_report.html": b"report",
            "report/capture_report.pdf": b"pdf",
            "network/dns.json": b"{}",
            "network/whois.txt": b"",
            "network/tls_certificate.json": b"{}",
            "timestamp/request.tsq": b"request",
            "timestamp/response.tsr": b"response",
            "timestamp/timestamp_info.json": b"{}",
            "timestamp/verify.sh": b"#!/bin/sh\n",
            "timestamp/verify.ps1": b"# verify\n",
            "VERIFICATION.md": b"verification",
        }
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in names.items():
                archive.writestr(name, data)

    def test_sha512_mismatch_fails(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            self._write_package(package, "0" * 128)
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("SHA-512 MISMATCH", result.output)

    def test_missing_timestamp_fails(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            self._write_package(package, hashlib.sha512(b"primary evidence").hexdigest())
            with zipfile.ZipFile(package, "r") as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            members["timestamp/response.tsr"] = b""
            with zipfile.ZipFile(package, "w") as archive:
                for name, data in members.items():
                    archive.writestr(name, data)
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Timestamp files are empty", result.output)

    def test_missing_package_binding_fails(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            self._write_package(package, hashlib.sha512(b"primary evidence").hexdigest())
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Package-wide timestamp binding is missing", result.output)

    def test_missing_manifest_hash_fails_closed(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            self._write_package(package, hashlib.sha512(b"primary evidence").hexdigest())
            with zipfile.ZipFile(package, "r") as archive:
                members = {
                    name: archive.read(name)
                    for name in archive.namelist()
                    if name != "manifest.sha256"
                }
            with zipfile.ZipFile(package, "w") as archive:
                for name, data in members.items():
                    archive.writestr(name, data)
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("manifest.sha256 is missing or empty", result.output)

    def test_malformed_manifest_fails_closed(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("manifest.json", b"{")
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("manifest.json is not valid JSON", result.output)

    def test_invalid_artifact_object_fails_without_crashing(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            package = pathlib.Path("package.zip")
            manifest = json.dumps({"schema_version": "1.1", "artifacts": None}).encode()
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("manifest.sha256", hashlib.sha256(manifest).hexdigest())
            result = runner.invoke(cli, ["verify", str(package)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("artifacts must be a non-empty object", result.output)


if __name__ == "__main__":
    unittest.main()