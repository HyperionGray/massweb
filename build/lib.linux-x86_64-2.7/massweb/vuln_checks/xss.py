from massweb.vuln_checks.match import parse_match
from massweb.vuln_checks.check import Check

class XSSCheck(Check):

    def __init__(self):

        self.vuln_string = "alert(31337)"

    def check(self, content):
        
        return parse_match(content, "script", self.vuln_string)
