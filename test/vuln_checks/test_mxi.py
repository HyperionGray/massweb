import unittest

from util import expand_cases
from massweb.vuln_checks import mxi

class TestMXICheck(unittest.TestCase):

    def setUp(self):
        true = ["unexpected extra arguments to select",
                "bad or malformed request",
                "could not access the following folders",
                "invalid mailbox name",
                "go to the folders page"]
        self.true = expand_cases(true)
        self.false = expand_cases(['', "mary had a little lamb", "i want to be an edge case"])

    def test_mxi_check(self):
        m = mxi.MXICheck()
        for t in self.true:
            self.assertTrue(m.check(t))
        for f in self.false:
            self.assertFalse(m.check(f))


if __name__ == "__main__":
    unittest.main()

