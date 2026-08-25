import gzip
import io
import pathlib
import sys
import unittest

from warcio.archiveiterator import ArchiveIterator

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from evidence.warc_writer import build_warc, validate_warc_bytes


def _http_result() -> dict:
    return {
        "status_code": 200,
        "reason": "OK",
        "final_url": "https://example.test/a?q=1",
        "request_headers": {"Host": "example.test"},
        "response_headers": {"Content-Type": "text/html"},
        "raw_body": b"<html>ok</html>",
    }


class TestWarcWriter(unittest.TestCase):

    def test_build_warc_is_parseable_and_preserves_request_target(self):
        data = build_warc(
            "https://example.test/a?q=1",
            _http_result(),
            {},
            "Operator",
            "CASE",
        )

        validate_warc_bytes(data)
        records = []
        response_body = b""
        for record in ArchiveIterator(gzip.GzipFile(fileobj=io.BytesIO(data))):
            records.append(record.rec_type)
            if record.rec_type == "request":
                self.assertEqual(record.http_headers.protocol, "GET")
                self.assertEqual(record.http_headers.statusline, "/a?q=1 HTTP/1.1")
            if record.rec_type == "response":
                response_body = record.content_stream().read()
        self.assertEqual(records, ["warcinfo", "request", "response"])
        self.assertEqual(response_body, b"<html>ok</html>")

    def test_empty_warc_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_warc_bytes(b"")

    def test_invalid_warc_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_warc_bytes(b"not gzip")


if __name__ == "__main__":
    unittest.main()