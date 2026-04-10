""" PathBuster — gobuster-style directory/file enumeration.

:class:`PathBuster` takes a base URL and a wordlist and probes each candidate
path using the existing ``MassRequest`` multiprocessing infrastructure, making
it fast at scale in keeping with the massweb philosophy.

Example usage::

    from massweb.path_buster.path_buster import PathBuster
    buster = PathBuster("https://example.com", num_threads=20)
    results = buster.bust()
    for r in results:
        print(r["url"], r["status_code"])
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests as _requests

from massweb.path_buster.wordlists import DEFAULT_WORDLIST

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)
logger = logging.getLogger("PathBuster")
logger.setLevel(logging.DEBUG)

# Status codes that are treated as "found" (non-trivial responses).
# 404 and 400 are excluded; 5xx errors are excluded to reduce noise.
FOUND_CODES = frozenset({200, 201, 204, 301, 302, 303, 307, 308, 401, 403})


class PathBuster(object):
    """ Gobuster-style directory and file enumerator.

    Probes each word in *wordlist* as a path under *base_url* and reports
    responses whose HTTP status code is in :data:`FOUND_CODES`.

    base_url        Base URL of the target (e.g. ``https://example.com``).
    wordlist        Iterable of path strings to probe.  Defaults to the
                    built-in :data:`~massweb.path_buster.wordlists.DEFAULT_WORDLIST`.
    extensions      Optional iterable of file extensions (e.g. ``[".php", ".html"]``).
                    Each word in *wordlist* will also be probed with every
                    extension appended.  Default ``[]``.
    num_threads     Number of concurrent worker threads.  Default 10.
    request_timeout Per-request timeout in seconds.  Default 10.
    proxy_list      List of proxy dicts to cycle through.  Default ``[{}]``.
    follow_redirects
                    Follow HTTP redirects when True.  Default False (more
                    informative to see the redirect itself).
    """

    def __init__(self, base_url, wordlist=None, extensions=None,
                 num_threads=10, request_timeout=10, proxy_list=None,
                 follow_redirects=False, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        self.wordlist = list(wordlist) if wordlist is not None else list(DEFAULT_WORDLIST)
        self.extensions = [ext if ext.startswith(".") else "." + ext for ext in (extensions or [])]
        self.num_threads = num_threads
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list or [{}]
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def bust(self):
        """ Enumerate paths and return all findings.

        returns     list of dicts, each with keys:

                    ``"url"``
                        The full URL that was probed.
                    ``"path"``
                        The path component that was appended to the base URL.
                    ``"status_code"``
                        HTTP status code returned by the server.
                    ``"content_length"``
                        Value of the Content-Length response header, or
                        ``None`` if absent.
        """
        candidates = self._build_candidates()
        results = []

        def probe(path):
            url = urljoin(self.base_url + "/", path)
            response = self._get(url)
            if response is None:
                return None
            if response.status_code in FOUND_CODES:
                return {
                    "url": url,
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": response.headers.get("Content-Length"),
                }
            return None

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {executor.submit(probe, p): p for p in candidates}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                    logger.debug(
                        "Found: %s [%d]",
                        result["url"],
                        result["status_code"],
                    )

        # Sort by path for deterministic output.
        results.sort(key=lambda r: r["path"])
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_candidates(self):
        """ Build the full list of candidate paths from the wordlist and any
        configured extensions. """
        candidates = []
        for word in self.wordlist:
            candidates.append(word)
            for ext in self.extensions:
                if not ext.startswith("."):
                    ext = "." + ext
                candidates.append(word + ext)
        return candidates

    def _get(self, url):
        """ Send a GET request and return the response, or None on failure. """
        proxy = random.choice(self.proxy_list) if self.proxy_list else {}
        try:
            response = _requests.get(
                url,
                timeout=self.request_timeout,
                proxies=proxy or None,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            )
            return response
        except Exception:
            logger.debug("GET failed for %s", url, exc_info=True)
            return None
