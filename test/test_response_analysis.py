import unittest

from requests import Response

from massweb.mass_requests.response_analysis import parse_worthy


def _make_response(url="http://example.test/", content_type="text/html; charset=utf-8",
                   body=b"<html></html>", content_length=None):
    """Build a minimal requests.Response for testing."""
    r = Response()
    r.status_code = 200
    r.url = url
    r._content = body
    r.headers = {"content-type": content_type}
    if content_length is not None:
        r.headers["content-length"] = str(content_length)
    else:
        r.headers["content-length"] = str(len(body))
    return r


class TestParseWorthy(unittest.TestCase):

    def test_text_html_is_parse_worthy(self):
        r = _make_response(content_type="text/html; charset=utf-8")
        self.assertTrue(parse_worthy(r))

    def test_text_plain_is_parse_worthy(self):
        r = _make_response(content_type="text/plain")
        self.assertTrue(parse_worthy(r))

    def test_non_text_content_type_not_parse_worthy(self):
        r = _make_response(content_type="application/pdf")
        self.assertFalse(parse_worthy(r))

    def test_missing_content_type_not_parse_worthy(self):
        r = _make_response()
        del r.headers["content-type"]
        self.assertFalse(parse_worthy(r))

    def test_oversized_response_not_parse_worthy(self):
        r = _make_response(content_length=6000000)
        self.assertFalse(parse_worthy(r))

    def test_exactly_at_default_limit_is_parse_worthy(self):
        r = _make_response(content_length=5000000)
        self.assertTrue(parse_worthy(r))

    def test_non_response_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_worthy("not a response object")

    def test_no_content_length_header_uses_body_size(self):
        body = b"<html>small</html>"
        r = _make_response(body=body)
        del r.headers["content-length"]
        self.assertTrue(parse_worthy(r))


if __name__ == "__main__":
    unittest.main()
