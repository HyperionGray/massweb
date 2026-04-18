""" XML External Entity (XXE) Injection Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class XXECheck(Check):
    """ XML External Entity (XXE) Injection Checker: Checks for evidence of
        successful XXE injection in result from fuzzers.

        XXE occurs when an XML parser processes an external entity reference
        supplied by the attacker. A successful exploit can read arbitrary local
        files, perform SSRF, or cause denial of service. Detection is based on
        XML parser error messages that indicate DTD/entity processing, or on
        file content that a vulnerable parser would include in the response.

        Strings are chosen for low false-positive rate: each one is strongly
        associated with XXE exploitation or XML parser error output and is
        very unlikely to appear in normal application responses. """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response. """
        vuln_strings_raw = [
            # Generic XML external-entity error messages
            "failed to load external entity",
            "external entity",
            # PHP (libxml) DTD/entity processing messages
            "dtd are not allowed",
            "external entities are not allowed",
            "doctype declarations not allowed",
            "doctypedecl is not allowed",
            # Java (Xerces/SAX) external entity errors
            "com.sun.org.apache.xerces",
            "javax.xml.parsers.saxparserexception",
            "external general entity",
            "feature 'http://apache.org/xml/features/disallow-doctype-decl'",
            # .NET System.Xml errors
            "system.xml.xmlexception",
            "dtd is prohibited",
            "for security reasons dtd",
            # Python lxml external-entity messages
            "xmlsyntaxerror",
            "failed to load http",
            # File content that a successful XXE read of /etc/passwd would expose
            "root:x:0:0",
            "daemon:x:",
            "nobody:x:",
            # Windows file content from /windows/win.ini or boot.ini
            "[boot loader]",
            "[fonts]",
            "[extensions]",
        ]
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
