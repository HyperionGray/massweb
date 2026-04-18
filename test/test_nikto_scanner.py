""" Tests for NiktoScanner and its header/path checks.

All tests are offline — no network requests are made. """

import unittest
from unittest.mock import MagicMock, patch

from massweb.nikto_scanner.header_checks import (
    audit_headers,
    check_clickjacking,
    check_cors,
    check_insecure_headers,
    check_missing_security_headers,
)
from massweb.nikto_scanner.nikto_scanner import NiktoScanner


def _mock_response(headers=None, status_code=200):
    """ Build a minimal mock response object. """
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = ""
    return response


class TestHeaderChecks(unittest.TestCase):

    def test_missing_all_security_headers(self):
        resp = _mock_response(headers={})
        findings = check_missing_security_headers(resp)
        self.assertGreater(len(findings), 0)
        labels = " ".join(findings)
        self.assertIn("Strict-Transport-Security", labels)
        self.assertIn("X-Content-Type-Options", labels)
        self.assertIn("X-Frame-Options", labels)

    def test_no_missing_headers_when_all_present(self):
        resp = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        findings = check_missing_security_headers(resp)
        self.assertEqual(findings, [])

    def test_version_disclosure_in_server_header(self):
        resp = _mock_response(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        findings = check_insecure_headers(resp)
        self.assertTrue(any("Apache" in f or "Version disclosed" in f for f in findings),
                        msg="Expected version disclosure finding, got: %s" % findings)

    def test_no_findings_for_clean_server_header(self):
        # No Server header present → no finding from insecure headers check
        resp = _mock_response(headers={})
        findings = check_insecure_headers(resp)
        self.assertEqual(findings, [])

    def test_permissive_cors_detected(self):
        resp = _mock_response(headers={"Access-Control-Allow-Origin": "*"})
        findings = check_cors(resp)
        self.assertTrue(any("CORS" in f or "permissive" in f for f in findings),
                        msg="Expected CORS finding, got: %s" % findings)

    def test_no_cors_finding_for_specific_origin(self):
        resp = _mock_response(headers={"Access-Control-Allow-Origin": "https://example.com"})
        findings = check_cors(resp)
        self.assertEqual(findings, [])

    def test_clickjacking_detected_when_no_protection(self):
        resp = _mock_response(headers={})
        findings = check_clickjacking(resp)
        self.assertGreater(len(findings), 0)

    def test_no_clickjacking_with_xfo(self):
        resp = _mock_response(headers={"X-Frame-Options": "DENY"})
        findings = check_clickjacking(resp)
        self.assertEqual(findings, [])

    def test_no_clickjacking_with_csp_frame_ancestors(self):
        resp = _mock_response(headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"
        })
        findings = check_clickjacking(resp)
        self.assertEqual(findings, [])

    def test_audit_headers_returns_combined(self):
        resp = _mock_response(headers={"Server": "nginx/1.18.0"})
        findings = audit_headers(resp)
        # Should include missing-header findings AND version-disclosure
        self.assertGreater(len(findings), 1)


class TestNiktoScannerUnit(unittest.TestCase):
    """ Unit tests for NiktoScanner using mocked HTTP responses. """

    def _make_scanner(self):
        return NiktoScanner("http://example.test", paths=["admin/", ".env"],
                            num_threads=2, request_timeout=5)

    @patch("massweb.nikto_scanner.nikto_scanner._requests.get")
    @patch("massweb.nikto_scanner.nikto_scanner._requests.options")
    def test_scan_detects_sensitive_path(self, mock_options, mock_get):
        # OPTIONS returns nothing dangerous
        mock_options.return_value = _mock_response(headers={"Allow": "GET, POST, HEAD"})

        # Base URL returns headers that are clean
        base_resp = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        # admin/ returns 200, .env returns 404
        def get_side_effect(url, **kwargs):
            if "admin" in url:
                return _mock_response(status_code=200)
            if ".env" in url:
                return _mock_response(status_code=404)
            return base_resp

        mock_get.side_effect = get_side_effect

        scanner = self._make_scanner()
        results = scanner.scan()

        self.assertIn("admin/", [p for p, _ in results["found_paths"]])
        self.assertNotIn(".env", [p for p, _ in results["found_paths"]])

    @patch("massweb.nikto_scanner.nikto_scanner._requests.get")
    @patch("massweb.nikto_scanner.nikto_scanner._requests.options")
    def test_scan_detects_dangerous_methods(self, mock_options, mock_get):
        mock_options.return_value = _mock_response(
            headers={"Allow": "GET, POST, PUT, DELETE, HEAD"}
        )
        mock_get.return_value = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })

        scanner = NiktoScanner("http://example.test", paths=[],
                               num_threads=2, request_timeout=5)
        results = scanner.scan()

        self.assertIn("PUT", results["dangerous_methods"])
        self.assertIn("DELETE", results["dangerous_methods"])
        any_finding = any("PUT" in f or "DELETE" in f for f in results["findings"])
        self.assertTrue(any_finding,
                        msg="Expected dangerous-method findings, got: %s" % results["findings"])

    @patch("massweb.nikto_scanner.nikto_scanner._requests.get")
    @patch("massweb.nikto_scanner.nikto_scanner._requests.options")
    def test_scan_reports_connection_failure(self, mock_options, mock_get):
        mock_options.return_value = _mock_response(headers={})
        mock_get.return_value = None  # Simulate failure

        scanner = NiktoScanner("http://unreachable.test", paths=[],
                               num_threads=1, request_timeout=1)
        # _get returns None: scan should report a connection error finding
        with patch.object(scanner, "_get", return_value=None):
            results = scanner.scan()
        self.assertTrue(any("Could not connect" in f for f in results["findings"]))


if __name__ == "__main__":
    unittest.main()
