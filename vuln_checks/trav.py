from vuln_checks.match import match_strings
from vuln_checks.check import Check

class TravCheck(Check):

    def __init__(self):

        self.vuln_string = ["root:x:", "[font]"]

    def check(self, content):

        content = content.lower()
        return match_strings(content, self.vuln_string)
