""" Mail Form Injection Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check

class MXICheck(Check):
    """ Mail Form Injection Checker: Checks for evidence of successful mail
        form injection in result from fuzzers. """
        #FIXME: Add brief description of attack

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response """
        vuln_strings_raw = ["unexpected extra arguments to select",
                            "bad or malformed request",
                            "could not access the following folders",
                            "invalid mailbox name", "go to the folders page"]
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
