""" NiktoScanner — lean, low-false-positive Nikto-style web scanner.

NiktoScanner combines:

* HTTP security-header auditing (via :mod:`massweb.nikto_scanner.header_checks`)
* Detection of dangerous HTTP methods (OPTIONS probe)
* Server software version disclosure detection
* Dangerous / sensitive path probing

It uses the existing :class:`~massweb.mass_requests.mass_request.MassRequest`
infrastructure for parallelised, rate-limited requests.

Example usage::

    from massweb.nikto_scanner.nikto_scanner import NiktoScanner
    scanner = NiktoScanner("https://example.com", num_threads=10)
    results = scanner.scan()
    for finding in results["findings"]:
        print(finding)
"""

import logging
from urllib.parse import urljoin

import requests as _requests

from massweb.nikto_scanner.header_checks import audit_headers
from massweb.nikto_scanner.path_lists import DEFAULT_PATHS

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)
logger = logging.getLogger("NiktoScanner")
logger.setLevel(logging.DEBUG)

# HTTP methods that are considered dangerous when enabled on the server.
DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


class NiktoScanner(object):
    """ Nikto-style scanner for a single web target.

    Performs header auditing, dangerous-method detection, and sensitive-path
    probing against *base_url*.

    base_url        Base URL of the target (e.g. ``https://example.com``).
    paths           List of path strings to probe.  Defaults to the built-in
                    :data:`~massweb.nikto_scanner.path_lists.DEFAULT_PATHS`.
    num_threads     Number of concurrent request workers.  Default 10.
    request_timeout Per-request timeout in seconds.  Default 10.
    proxy_list      List of proxy dicts to cycle through.  Default [{}].
    """

    def __init__(self, base_url, paths=None, num_threads=10,
                 request_timeout=10, proxy_list=None, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        self.paths = paths if paths is not None else list(DEFAULT_PATHS)
        self.num_threads = num_threads
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list or [{}]
        self.verify_ssl = verify_ssl

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self):
        """ Run all Nikto-style checks against the target.

        returns     dict with keys:

                    ``"base_url"``
                        The base URL that was scanned.
                    ``"findings"``
                        list of str, one entry per finding.
                    ``"found_paths"``
                        list of (path, status_code) tuples for paths that
                        returned a non-404 response.
                    ``"dangerous_methods"``
                        list of HTTP method strings that are enabled on the
                        server according to the OPTIONS response.
        """
        findings = []
        found_paths = []
        dangerous_methods = []

        # 1. Fetch the base URL and audit its headers.
        base_response = self._get(self.base_url)
        if base_response is not None:
            header_findings = audit_headers(base_response)
            findings.extend(header_findings)
        else:
            findings.append("Could not connect to base URL: %s" % self.base_url)

        # 2. Probe for dangerous HTTP methods.
        dangerous_methods = self._check_dangerous_methods()
        for method in dangerous_methods:
            findings.append("Dangerous HTTP method enabled: %s" % method)

        # 3. Probe sensitive / dangerous paths in parallel.
        found_paths = self._probe_paths()
        for path, status in found_paths:
            findings.append(
                "Sensitive path accessible (HTTP %d): %s" % (status, path)
            )

        return {
            "base_url": self.base_url,
            "findings": findings,
            "found_paths": found_paths,
            "dangerous_methods": dangerous_methods,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, url):
        """ Send a GET request and return the response, or None on failure. """
        proxy = random.choice(self.proxy_list) if self.proxy_list else {}
        try:
            response = _requests.get(
                url,
                timeout=self.request_timeout,
                proxies=proxy or None,
                allow_redirects=False,
                verify=self.verify_ssl,
            )
            return response
        except Exception:
            logger.debug("GET failed for %s", url, exc_info=True)
            return None

    def _options(self, url):
        """ Send an OPTIONS request and return the response, or None on
        failure. """
        proxy = self.proxy_list[0] if self.proxy_list else {}
        try:
            response = _requests.options(
                url,
                timeout=self.request_timeout,
                proxies=proxy or None,
                verify=self.verify_ssl,
            )
            return response
        except Exception:
            logger.debug("OPTIONS failed for %s", url, exc_info=True)
            return None

    def _check_dangerous_methods(self):
        """ Use OPTIONS to detect dangerous HTTP methods enabled on the server.

        returns     list of dangerous method name strings.
        """
        response = self._options(self.base_url)
        if response is None:
            return []
        allow_header = response.headers.get("Allow", "") or response.headers.get("Public", "")
        enabled = {m.strip().upper() for m in allow_header.split(",")}
        return sorted(enabled & DANGEROUS_METHODS)

    def _probe_paths(self):
        """ Probe all configured paths and return those that are accessible.

        A path is considered accessible when the server returns a status code
        other than 404, 400, or 5xx.  This keeps the false-positive rate low
        by ignoring server errors and explicit not-found responses.

        returns     list of (path, status_code) tuples.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def probe(path):
            url = urljoin(self.base_url + "/", path)
            response = self._get(url)
            if response is None:
                return None
            code = response.status_code
            # Report 200, 201, 301, 302, 303, 307, 308, 401, 403 as findings.
            # Exclude 404 (not found) and 5xx (server errors) to reduce noise.
            if code in (200, 201, 301, 302, 303, 307, 308, 401, 403):
                return (path, code)
            return None

        found = []
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {executor.submit(probe, p): p for p in self.paths}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    found.append(result)
        return found
