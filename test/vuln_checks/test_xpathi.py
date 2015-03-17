
import unittest
from util import expand_cases
from massweb.vuln_checks import xpathi

class TestXPathICheck(unittest.TestCase):

    def setUp(self):
        true = ['System.Xml.XPath.XPathException:',
                'MS.Internal.Xml.',
                'Unknown error in XPath',
                'org.apache.xpath.XPath',
                'A closing bracket expected in',
                'An operand in Union Expression does not produce a node-set',
                'Cannot convert expression to a number',
                'Document Axis does not allow any context Location Steps',
                'Empty Path Expression',
                'DOMXPath::'
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
        self.true = expand_cases([x.lower() for x in true])
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]

    def test_xpathi_check(self):
        x = xpathi.XPathICheck()
        for t in self.true:
            self.assertTrue(x.check(t))
        for f in self.false:
            self.assertFalse(x.check(f))


if __name__ == "__main__":
    unittest.main()

