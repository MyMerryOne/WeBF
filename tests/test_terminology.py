"""Regression checks for WeBF-authored product terminology."""
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
SOURCE_FILES = (
    "README.md",
    "pyproject.toml",
    "webf.py",
    "packaging/bundler.py",
    "packaging/manifest.py",
    "packaging/report.py",
    "templates/report_base.html.j2",
    "templates/report_eu.html.j2",
    "templates/report_it.html.j2",
    "templates/report_cz.html.j2",
)


class TestProductTerminology(unittest.TestCase):
    def test_source_authored_output_does_not_use_banned_product_labels(self):
        banned = ("forensic", "court-ready")
        for relative_path in SOURCE_FILES:
            content = (ROOT / relative_path).read_text(encoding="utf-8").lower()
            for term in banned:
                self.assertNotIn(term, content, relative_path)


if __name__ == "__main__":
    unittest.main()