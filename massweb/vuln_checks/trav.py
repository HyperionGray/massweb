""" Directory Traversal Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class TravCheck(Check):
    """ Directory Traversal Checker: Checks for evidence of successful
        directory traversal in result from fuzzers.

        Directory traversal (path traversal) occurs when an attacker uses
        sequences such as ``../../`` to access files outside the intended
        directory. A successful exploit can expose sensitive files such as
        ``/etc/passwd`` on Unix systems or ``win.ini`` on Windows systems. """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response """
        vuln_strings_raw = [
            # Unix /etc/passwd indicators
            "root:x:",
            "root:*:",
            "daemon:x:",
            "nobody:x:",
            # Unix /etc/shadow indicators (hashed passwords)
            "root:$1$",
            "root:$2a$",
            "root:$6$",
            # Windows win.ini indicators
            "[font",
            "[windows]",
            "[extensions]",
            # Windows boot.ini indicators
            "[boot loader]",
            "[operating systems]",
            # Windows system32 directory listing indicator
            "\\system32\\",
        ]
        self.vuln_string = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_string)
