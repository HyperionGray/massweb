import unittest
from massweb.vuln_checks import ssrf


class TestSSRFCheck(unittest.TestCase):

    def setUp(self):
        self.true = [
            "ami-id",
            "instance-id",
            "instance-type",
            "local-hostname",
            "local-ipv4",
            "computemetadata",
            "redis_version",
            "memcached stats",
            "failed to connect to",
            "connection refused",
            '"status":"up"',
            '"diskspace":{',
        ]
        self.false = ['', "mary had a little lamb", "normal page content"]

    def test_ssrf_check(self):
        s = ssrf.SSRFCheck()
        for t in self.true:
            self.assertTrue(s.check(t), msg=f"Expected SSRF match for: {t!r}")
        for f in self.false:
            self.assertFalse(s.check(f), msg=f"Expected no SSRF match for: {f!r}")


if __name__ == "__main__":
    unittest.main()
