import unittest
from unittest.mock import Mock, patch

from capture.browser import _guard_navigation


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

    def test_allows_non_network_browser_scheme(self):
        route = Mock()
        request = Mock(url="data:text/plain,fixture", is_navigation_request=lambda: False)
        with patch("capture.browser.validate_public_url") as validate:
            _guard_navigation(route, request)

        validate.assert_not_called()
        route.continue_.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
