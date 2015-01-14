
import unittest
from massweb.vuln_checks import osci

class TestOSCICheck(unittest.TestCase):

    def setUp(self):
        self.true = ["root:x:", "[font]"]
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]


    def test_osci_check(self):
        o = osci.OSCICheck()
        for t in self.true:
            self.assertTrue(o.check(t))
        for f in self.false:
            self.assertFalse(o.check(f))


if __name__ == "__main__":
    unittest.main()

