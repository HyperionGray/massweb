
import unittest
from massweb.vuln_checks import osci

class TestOSCICheck(unittest.TestCase):

    def setUp(self):
        self.true = [
            # Unix /etc/passwd content
            "root:x:",
            # Unix id command output
            "uid=0(root)",
            "uid=0(",
            # Common Unix shell paths
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/",
            # Windows indicators
            "volume in drive",
            "volume serial number",
            "directory of c:\\",
            "windows ip configuration",
            "ipv4 address",
            "subnet mask",
            "default gateway",
            "the command completed successfully",
            "local group memberships",
        ]
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]


    def test_osci_check(self):
        o = osci.OSCICheck()
        for t in self.true:
            self.assertTrue(o.check(t), msg=f"Expected OSCI match for: {t!r}")
        for f in self.false:
            self.assertFalse(o.check(f), msg=f"Expected no OSCI match for: {f!r}")


if __name__ == "__main__":
    unittest.main()

