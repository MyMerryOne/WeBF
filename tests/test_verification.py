import hashlib
import json
import pathlib
import sys
import unittest
import zipfile

from click.testing import CliRunner

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from webf import _package_inventory, _unsafe_package_members, cli


class TestPackageInventory(unittest.TestCase):

    def test_reports_missing_and_unexpected_members(self):
        manifest = {
            "artifacts": {"capture/page.warc.gz": {"sha256": "a", "sha512": "b"}}
        }
        missing, unexpected = _package_inventory(
            manifest,
            ["manifest.json", "manifest.sha256", "capture/page.warc.gz", "extra.txt"],
        )

        self.assertIn("report/forensic_report.html", missing)
        self.assertIn("extra.txt", unexpected)

    def test_detects_unsafe_member_paths(self):
        unsafe = _unsafe_package_members(["capture/page.warc.gz", "../outside", "/absolute"])

        self.assertEqual(unsafe, {"../outside", "/absolute"})


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
            "report/forensic_report.html": b"report",
            "report/forensic_report.pdf": b"pdf",
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


if __name__ == "__main__":
    unittest.main()