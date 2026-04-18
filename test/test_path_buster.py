""" Tests for PathBuster.

All tests are offline — HTTP responses are mocked. """

import unittest
from unittest.mock import MagicMock, patch

from massweb.path_buster.path_buster import FOUND_CODES, PathBuster
from massweb.path_buster.wordlists import DEFAULT_WORDLIST


def _mock_response(status_code=200, content_length=None):
    response = MagicMock()
    response.status_code = status_code
    headers = {}
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
    response.headers = headers
    return response


class TestPathBusterUnit(unittest.TestCase):

    def _make_buster(self, wordlist=None):
        return PathBuster(
            "http://example.test",
            wordlist=wordlist or ["admin", "backup", "notfound"],
            num_threads=2,
            request_timeout=5,
        )

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_returns_found_paths(self, mock_get):
        def get_side_effect(url, **kwargs):
            if "admin" in url:
                return _mock_response(status_code=200, content_length=512)
            if "backup" in url:
                return _mock_response(status_code=403)
            return _mock_response(status_code=404)

        mock_get.side_effect = get_side_effect

        buster = self._make_buster()
        results = buster.bust()

        paths = [r["path"] for r in results]
        self.assertIn("admin", paths)
        self.assertIn("backup", paths)
        self.assertNotIn("notfound", paths)

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_excludes_404(self, mock_get):
        mock_get.return_value = _mock_response(status_code=404)

        buster = self._make_buster(wordlist=["admin", "backup"])
        results = buster.bust()
        self.assertEqual(results, [])

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_result_structure(self, mock_get):
        mock_get.return_value = _mock_response(status_code=200, content_length=100)

        buster = self._make_buster(wordlist=["admin"])
        results = buster.bust()

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertIn("url", result)
        self.assertIn("path", result)
        self.assertIn("status_code", result)
        self.assertIn("content_length", result)
        self.assertEqual(result["path"], "admin")
        self.assertEqual(result["status_code"], 200)

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_with_extensions(self, mock_get):
        def get_side_effect(url, **kwargs):
            if url.endswith(".php"):
                return _mock_response(status_code=200)
            return _mock_response(status_code=404)

        mock_get.side_effect = get_side_effect

        buster = PathBuster(
            "http://example.test",
            wordlist=["admin"],
            extensions=[".php", ".html"],
            num_threads=2,
            request_timeout=5,
        )
        results = buster.bust()
        paths = [r["path"] for r in results]
        self.assertIn("admin.php", paths)
        self.assertNotIn("admin", paths)
        self.assertNotIn("admin.html", paths)

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_handles_connection_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")

        buster = self._make_buster(wordlist=["admin"])
        # Should not raise; failed requests are silently skipped.
        results = buster.bust()
        self.assertEqual(results, [])

    def test_default_wordlist_is_nonempty(self):
        self.assertGreater(len(DEFAULT_WORDLIST), 0)

    def test_found_codes_contains_common_codes(self):
        for code in (200, 301, 302, 401, 403):
            self.assertIn(code, FOUND_CODES)

    def test_found_codes_excludes_404(self):
        self.assertNotIn(404, FOUND_CODES)

    @patch("massweb.path_buster.path_buster._requests.get")
    def test_bust_results_sorted_by_path(self, mock_get):
        mock_get.return_value = _mock_response(status_code=200)

        buster = PathBuster(
            "http://example.test",
            wordlist=["zebra", "alpha", "mango"],
            num_threads=2,
            request_timeout=5,
        )
        results = buster.bust()
        paths = [r["path"] for r in results]
        self.assertEqual(paths, sorted(paths))


if __name__ == "__main__":
    unittest.main()
