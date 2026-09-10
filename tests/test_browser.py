import unittest
from unittest.mock import Mock, patch

from capture.browser import _guard_navigation, _isolated_egress_proxy


class TestBrowserRequestPolicy(unittest.TestCase):
    def test_blocks_private_subresource(self):
        route = Mock()
        request = Mock(url="https://127.0.0.1/metadata", is_navigation_request=lambda: False)
        with patch("capture.browser.validate_public_url", side_effect=ValueError("private")):
            _guard_navigation(route, request)

        route.abort.assert_called_once_with(error_code="blockedbyclient")
        route.continue_.assert_not_called()

    def test_validates_public_subresource(self):
        route = Mock()
        request = Mock(url="https://cdn.example.test/script.js", is_navigation_request=lambda: False)
        with patch("capture.browser.validate_public_url") as validate:
            _guard_navigation(route, request)

        validate.assert_called_once_with(request.url)
        route.continue_.assert_called_once_with()

    def test_required_isolated_egress_fails_without_proxy(self):
        with patch.dict("os.environ", {"WEBF_REQUIRE_ISOLATED_EGRESS": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "WEBF_BROWSER_PROXY"):
                _isolated_egress_proxy()

    def test_isolated_egress_proxy_is_explicit(self):
        with patch.dict(
            "os.environ",
            {"WEBF_REQUIRE_ISOLATED_EGRESS": "1", "WEBF_BROWSER_PROXY": "http://proxy:8080"},
            clear=True,
        ):
            self.assertEqual(_isolated_egress_proxy(), {"server": "http://proxy:8080"})

    def test_allows_non_network_browser_scheme(self):
        route = Mock()
        request = Mock(url="data:text/plain,fixture", is_navigation_request=lambda: False)
        with patch("capture.browser.validate_public_url") as validate:
            _guard_navigation(route, request)

        validate.assert_not_called()
        route.continue_.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
