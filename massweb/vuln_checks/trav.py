""" Directory Traversal Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class TravCheck(Check):
    """ Directory Traversal Checker: Checks for evidence of successful
        directory traversal in result from fuzzers.

        Directory traversal (path traversal) occurs when an attacker uses
        sequences such as ``../../`` to access files outside the intended
        directory. A successful exploit can expose sensitive files such as
        ``/etc/passwd`` on Unix systems. """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response """
        self.vuln_string = ["root:x:", "[font]"]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_string)
