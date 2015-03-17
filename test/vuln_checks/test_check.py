import unittest
from massweb.vuln_checks import check

class TestCheck(unittest.TestCase):

    def test_check_check(self):
        c = check.Check()
        self.assertRaises(NotImplementedError, c.check, "anything")


if __name__ == "__main__":
    unittest.main()
