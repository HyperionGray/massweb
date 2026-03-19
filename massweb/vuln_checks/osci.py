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
        vuln_strings_raw = [
            # Unix /etc/passwd content (common OSCI payload: ; cat /etc/passwd)
            "root:x:",
            # Unix id command output: uid=0(root) gid=0(root) groups=0(root)
            "uid=0(root)",
            "uid=0(",
            # Common Unix shell paths that appear in command output
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/",
            # Windows command output patterns
            "volume in drive",
            "volume serial number",
            "directory of c:\\",
            "windows ip configuration",
            # Windows ipconfig/systeminfo indicators
            "ipv4 address",
            "subnet mask",
            "default gateway",
            # net user / whoami output patterns
            "the command completed successfully",
            "local group memberships",
        ]
        self.vuln_string = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_string)
