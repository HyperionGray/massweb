""" Cross (X) Site Scripting Checker """

from massweb.vuln_checks.match import parse_match
from massweb.vuln_checks.check import Check

class XSSCheck(Check):
    """ Cross (X) Site Scripting Checker: Checks for evidence of successful
        cross site scripting in result from fuzzers. """
        #FIXME: Add brief description of the attack

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response """
        self.vuln_string = "alert(31337)"

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        return parse_match(content, "script", self.vuln_string)
