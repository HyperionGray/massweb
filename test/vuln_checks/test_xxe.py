
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from util import expand_cases
from massweb.vuln_checks import xxe


class TestXXECheck(unittest.TestCase):

    def setUp(self):
        true = [
            # Generic external-entity error messages
            "failed to load external entity",
            "external entity",
            # PHP DTD errors
            "dtd are not allowed",
            "external entities are not allowed",
            "doctype declarations not allowed",
            "doctypedecl is not allowed",
            # Java parser errors
            "com.sun.org.apache.xerces",
            "javax.xml.parsers.saxparserexception",
            "external general entity",
            "feature 'http://apache.org/xml/features/disallow-doctype-decl'",
            # .NET XML errors
            "system.xml.xmlexception",
            "dtd is prohibited",
            "for security reasons dtd",
            # Python lxml messages
            "xmlsyntaxerror",
            "failed to load http",
            # /etc/passwd content exposed via XXE
            "root:x:0:0",
            "daemon:x:",
            "nobody:x:",
            # Windows file content
            "[boot loader]",
            "[fonts]",
            "[extensions]",
        ]
        self.true = expand_cases([x.lower() for x in true])
        self.false = [
            '',
            "mary had a little lamb",
            "i want to be an edge case",
            "<xml><data>normal content</data></xml>",
        ]

    def test_xxe_check_true_positives(self):
        c = xxe.XXECheck()
        for t in self.true:
            self.assertTrue(c.check(t), msg="Expected XXE match for: %r" % t)

    def test_xxe_check_true_negatives(self):
        c = xxe.XXECheck()
        for f in self.false:
            self.assertFalse(c.check(f), msg="Expected no XXE match for: %r" % f)


if __name__ == "__main__":
    unittest.main()
