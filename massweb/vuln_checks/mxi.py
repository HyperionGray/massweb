from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check

class MXICheck(Check):

    def __init__(self):

        vuln_strings_raw = ["unexpected extra arguments to select", 
                            "bad or malformed request", "could not access the following folders", 
                            "invalid mailbox name", "go to the folders page"]

        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        
        content = content.lower()
        return match_strings(content, self.vuln_strings)
