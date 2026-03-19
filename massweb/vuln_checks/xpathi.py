""" XPath Injection Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class XPathICheck(Check):
    """ XPath Injection Checker: Checks for evidence of successful XPath
        injection in result from fuzzers.

        XPath injection occurs when user-supplied input is embedded in an
        XPath query without proper sanitization. An attacker can alter query
        logic to extract data from XML documents or bypass authentication. """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response """
        vuln_strings_raw = ['System.Xml.XPath.XPathException:',
            'MS.Internal.Xml.',
            'Unknown error in XPath',
            'org.apache.xpath.XPath',
            'A closing bracket expected in',
            'An operand in Union Expression does not produce a node-set',
            'Cannot convert expression to a number',
            'Document Axis does not allow any context Location Steps',
            'Empty Path Expression',
            'DOMXPath::',
            'Empty Relative Location Path',
            'Empty Union Expression',
            "Expected ')' in",
            'Expected node test or name specification after axis operator',
            'Incompatible XPath key',
            'Incorrect Variable Binding',
            'libxml2 library function failed',
            'libxml2',
            'xmlsec library function',
            'xmlsec',
            "error '80004005'",
            "A document must contain exactly one root element.",
            '<font face="Arial" size=2>Expression must evaluate to a node-set.',
            "Expected token ']'",
            "<p>msxml4.dll</font>",
            "<p>msxml3.dll</font>",
            '4005 Notes error: Query is not understandable']
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
