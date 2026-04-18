""" Server-Side Include (SSI) Injection Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class SSICheck(Check):
    """ Server-Side Include (SSI) Injection Checker: Checks for evidence of
        successful SSI injection in result from fuzzers.

        SSI injection occurs when user-controlled input is passed to a page
        that is processed for SSI directives (``<!--#exec ...-->`` etc.) by the
        web server (typically Apache or nginx with SSI enabled). A successful
        exploit can execute arbitrary commands on the server.

        Strings are chosen for low false-positive rate: Apache/nginx SSI error
        messages and the output of ``<!--#exec cmd="id"-->`` are unlikely to
        appear in normal application responses. """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response. """
        vuln_strings_raw = [
            # Apache/nginx error rendered when an SSI directive fails
            "[an error occurred while processing this directive]",
            # Common Apache SSI include-file error
            "ssi: could not include file",
            # Output of <!--#exec cmd="id"--> on Unix — uid= prefix
            "uid=0(",
            "uid=",
            # Output of <!--#exec cmd="whoami"--> or <!--#printenv-->
            "document_name=",
            "server_name=",
            "date_local=",
            # nginx SSI error tag
            "<!--# error",
            # Generic directive-processing failure message used by several servers
            "error in ssi processing",
        ]
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
