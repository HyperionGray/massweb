
import unittest
from massweb.vuln_checks import trav

class TestTrav(unittest.TestCase):

    def setUp(self):
        self.true = ["root:x:", "[font]"]
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]
       
    def test_trav(self):
        tr = trav.TravCheck()
        for t in self.true:
            self.assertTrue(tr.check(t))
        for f in self.false:
            self.assertFalse(tr.check(f))


if __name__ == "__main__":
    unittest.main()

