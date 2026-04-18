import unittest
from unittest.mock import MagicMock
import requests
from requests import Response
from massweb.mass_requests.response_analysis import parse_worthy


def _make_response(content_type=None, content_length=None, content=b"hello",
                   url="http://example.test/"):
    """ Build a minimal requests.Response for testing. """
    resp = Response()
    resp.url = url
    resp._content = content
    if content_type is not None:
        resp.headers["content-type"] = content_type
    if content_length is not None:
        resp.headers["content-length"] = str(content_length)
    return resp


class TestParseWorthy(unittest.TestCase):

    def test_text_html_small_is_parse_worthy(self):
        resp = _make_response(content_type="text/html; charset=utf-8",
                              content_length=1000)
        self.assertTrue(parse_worthy(resp))

    def test_text_plain_small_is_parse_worthy(self):
        resp = _make_response(content_type="text/plain", content_length=100)
        self.assertTrue(parse_worthy(resp))

    def test_binary_content_type_not_parse_worthy(self):
        resp = _make_response(content_type="application/octet-stream",
                              content_length=100)
        self.assertFalse(parse_worthy(resp))

    def test_image_content_type_not_parse_worthy(self):
        resp = _make_response(content_type="image/png", content_length=500)
        self.assertFalse(parse_worthy(resp))

    def test_no_content_type_not_parse_worthy(self):
        resp = _make_response(content_length=100)
        self.assertFalse(parse_worthy(resp))

    def test_oversized_content_length_not_parse_worthy(self):
        resp = _make_response(content_type="text/html",
                              content_length=6000000)
        self.assertFalse(parse_worthy(resp))

    def test_exactly_at_max_parse_size_not_parse_worthy(self):
        resp = _make_response(content_type="text/html",
                              content_length=5000001)
        self.assertFalse(parse_worthy(resp))

    def test_custom_max_parse_size(self):
        resp = _make_response(content_type="text/html", content_length=200)
        self.assertFalse(parse_worthy(resp, max_parse_size=100))

    def test_custom_content_type_match(self):
        resp = _make_response(content_type="application/json",
                              content_length=100)
        self.assertTrue(parse_worthy(resp, content_type_match="application"))

    def test_non_response_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_worthy("not a response")

    def test_non_response_object_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_worthy(42)

    def test_no_content_length_header_uses_content_size(self):
        # No content-length header; actual content is small.
        resp = _make_response(content_type="text/html",
                              content=b"x" * 100)
        self.assertTrue(parse_worthy(resp))

    def test_no_content_length_oversized_content_not_parse_worthy(self):
        # No content-length header; actual content exceeds max_parse_size.
        resp = _make_response(content_type="text/html",
                              content=b"x" * 100)
        self.assertFalse(parse_worthy(resp, max_parse_size=10))


if __name__ == "__main__":
    unittest.main()
