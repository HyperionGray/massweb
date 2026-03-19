
import unittest
from massweb.vuln_checks import trav

class TestTrav(unittest.TestCase):

    def setUp(self):
        self.true = [
            # Unix /etc/passwd indicators
            "root:x:",
            "root:*:",
            "daemon:x:",
            "nobody:x:",
            # Unix /etc/shadow indicators
            "root:$1$",
            "root:$2a$",
            "root:$6$",
            # Windows win.ini indicators
            "[font",
            "[fonts]",
            "[windows]",
            "[extensions]",
            # Windows boot.ini indicators
            "[boot loader]",
            "[operating systems]",
            # Windows system32 indicator
            "\\system32\\",
        ]
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]

    def test_trav(self):
        tr = trav.TravCheck()
        for t in self.true:
            self.assertTrue(tr.check(t), msg=f"Expected traversal match for: {t!r}")
        for f in self.false:
            self.assertFalse(tr.check(f), msg=f"Expected no traversal match for: {f!r}")


if __name__ == "__main__":
    unittest.main()

