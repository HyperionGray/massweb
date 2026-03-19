""" OS Command Injection Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check

class OSCICheck(Check):
    """ OS Command Injection Checker: Checks for evidence of successful OS
        command injection in result from fuzzers.

        OS command injection occurs when user-supplied input is passed to a
        shell command without proper sanitization. An attacker can append
        additional commands to execute arbitrary code on the server, potentially
        gaining full control of the system. """

    def __init__(self):
        """ Initialize this object and the list of strings to check for in
            responses. """
        self.vuln_string = ["root:x:", "[font]"]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_string)
