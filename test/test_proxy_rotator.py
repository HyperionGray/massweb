""" Unit tests for massweb.proxy_rotator.proxy_rotate """

import unittest

from massweb.proxy_rotator.proxy_rotate import get_random_proxy


class TestGetRandomProxy(unittest.TestCase):

    def test_returns_entry_from_list(self):
        proxy_list = [{"http": "127.0.0.1"}, {"http": "127.0.0.2"}]
        result = get_random_proxy(proxy_list)
        self.assertIn(result, proxy_list)

    def test_single_entry_always_returned(self):
        proxy_list = [{"http": "127.0.0.1"}]
        for _ in range(10):
            result = get_random_proxy(proxy_list)
            self.assertEqual(result, {"http": "127.0.0.1"})

    def test_empty_list_raises(self):
        with self.assertRaises(IndexError):
            get_random_proxy([])

    def test_multiple_schemes(self):
        proxy_list = [
            {"http": "http://proxy1.example.com:8080"},
            {"https": "https://proxy2.example.com:8080"},
        ]
        result = get_random_proxy(proxy_list)
        self.assertIn(result, proxy_list)

    def test_distribution_covers_all_entries(self):
        proxy_list = [{"http": "127.0.0.%d" % i} for i in range(10)]
        seen = set()
        for _ in range(500):
            result = get_random_proxy(proxy_list)
            seen.add(result["http"])
        # With 500 draws from 10 items the chance of missing any one is
        # (9/10)^500 < 1e-22, so this is effectively deterministic.
        self.assertEqual(len(seen), len(proxy_list))


if __name__ == "__main__":
    unittest.main()
