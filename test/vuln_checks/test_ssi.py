
import unittest
from util import expand_cases
from massweb.vuln_checks import ssi


class TestSSICheck(unittest.TestCase):

    def setUp(self):
        true = [
            # Apache SSI directive-processing error
            "[an error occurred while processing this directive]",
            # Apache SSI include-file error
            "ssi: could not include file",
            # Output of <!--#exec cmd="id"-->
            "uid=0(",
            "uid=",
            # Output of <!--#printenv-->
            "document_name=",
            "server_name=",
            "date_local=",
            # nginx SSI error tag
            "<!--# error",
            # Generic SSI error message
            "error in ssi processing",
        ]
        self.true = expand_cases([x.lower() for x in true])
        self.false = [
            '',
            "mary had a little lamb",
            "i want to be an edge case",
            "<html><body>normal page content</body></html>",
        ]

    def test_ssi_check_true_positives(self):
        c = ssi.SSICheck()
        for t in self.true:
            self.assertTrue(c.check(t), msg="Expected SSI match for: %r" % t)

    def test_ssi_check_true_negatives(self):
        c = ssi.SSICheck()
        for f in self.false:
            self.assertFalse(c.check(f), msg="Expected no SSI match for: %r" % f)


if __name__ == "__main__":
    unittest.main()
