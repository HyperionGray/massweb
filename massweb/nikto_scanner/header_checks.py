""" Security-header auditing for the Nikto-style scanner.

Each function accepts a ``requests.Response`` object (or any object whose
``.headers`` attribute is a dict-like mapping) and returns a list of finding
strings describing the issue detected.  An empty list means no issues were
found for that check. """

import re


# Security headers that SHOULD be present and the minimum content we expect.
_REQUIRED_HEADERS = {
    "Strict-Transport-Security": None,
    "X-Content-Type-Options": None,
    "X-Frame-Options": None,
}

# Deprecated/insecure headers that SHOULD NOT be present.
_DEPRECATED_HEADERS = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "Server",
]

# Regex patterns for version strings that indicate software-version disclosure
# inside a Server or X-Powered-By header value.
_VERSION_PATTERN = re.compile(
    r"""
    ( apache  | nginx  | iis | litespeed | tomcat |
      lighttpd | openssl | php | mod_ssl | express )
    [/\s]+([\d.]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def check_missing_security_headers(response):
    """ Check for required security headers that are absent from the response.

    response    requests.Response (or compatible) object.

    returns     list of str describing each missing header.
    """
    findings = []
    for header in _REQUIRED_HEADERS:
        if header not in response.headers:
            findings.append("Missing security header: %s" % header)
    return findings


def check_insecure_headers(response):
    """ Check for deprecated or information-leaking headers in the response.

    response    requests.Response (or compatible) object.

    returns     list of str describing each problematic header found.
    """
    findings = []
    for header in _DEPRECATED_HEADERS:
        value = response.headers.get(header, "")
        if value:
            # Check for version disclosure within the header value.
            match = _VERSION_PATTERN.search(value)
            if match:
                findings.append(
                    "Version disclosed in header %s: %s" % (header, value)
                )
            else:
                findings.append(
                    "Information-leaking header present: %s: %s" % (header, value)
                )
    return findings


def check_cors(response):
    """ Check for overly permissive CORS configuration.

    A response that reflects ``Access-Control-Allow-Origin: *`` or mirrors
    the request origin without restriction is a likely misconfiguration.

    response    requests.Response (or compatible) object.

    returns     list of str describing CORS issues found.
    """
    findings = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        findings.append(
            "Overly permissive CORS policy: Access-Control-Allow-Origin: *"
        )
    return findings


def check_clickjacking(response):
    """ Check for clickjacking protection.

    Looks for the X-Frame-Options header or a Content-Security-Policy
    frame-ancestors directive.  If neither is present the page may be
    embeddable in an iframe.

    response    requests.Response (or compatible) object.

    returns     list of str describing clickjacking issues found.
    """
    findings = []
    xfo = response.headers.get("X-Frame-Options", "")
    csp = response.headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(
            "No clickjacking protection: X-Frame-Options header absent and "
            "Content-Security-Policy does not contain frame-ancestors"
        )
    return findings


def audit_headers(response):
    """ Run all header checks against a response and return combined findings.

    response    requests.Response (or compatible) object.

    returns     list of str, one entry per finding (empty if all checks pass).
    """
    findings = []
    findings.extend(check_missing_security_headers(response))
    findings.extend(check_insecure_headers(response))
    findings.extend(check_cors(response))
    findings.extend(check_clickjacking(response))
    return findings
