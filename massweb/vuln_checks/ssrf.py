""" Server-Side Request Forgery (SSRF) Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class SSRFCheck(Check):
    """ Server-Side Request Forgery Checker: Checks for evidence of successful
        SSRF in result from fuzzers.

        SSRF vulnerabilities allow an attacker to induce the server to make
        HTTP requests to an arbitrary domain, including internal services.
        Indicators include cloud metadata responses, internal service banners,
        and common SSRF error messages that leak internal host information.
    """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response. """
        vuln_strings_raw = [
            # AWS metadata service responses
            "ami-id",
            "instance-id",
            "instance-type",
            "local-hostname",
            "local-ipv4",
            "ami-launch-index",
            # GCP metadata service
            "computemetadata",
            "metadata.google.internal",
            # Azure metadata
            "metadata/instance",
            # Common internal service banners
            "redis_version",
            "memcached stats",
            # Error messages that reveal internal host details
            "failed to connect to",
            "connection refused",
            "no route to host",
            "name or service not known",
            "could not resolve host",
            # Spring Boot actuator (often exposed internally)
            "\"status\":\"up\"",
            "\"diskspace\":{",
        ]
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
