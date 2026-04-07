import unittest
from massweb.proxy_rotator.proxy_rotate import get_random_proxy


class TestGetRandomProxy(unittest.TestCase):

    def test_returns_item_from_list(self):
        proxy_list = [{"http": "127.0.0.1"}, {"http": "127.0.0.2"}]
        result = get_random_proxy(proxy_list)
        self.assertIn(result, proxy_list)

    def test_single_proxy_always_returned(self):
        proxy_list = [{"http": "10.0.0.1"}]
        for _ in range(10):
            result = get_random_proxy(proxy_list)
            self.assertEqual(result, {"http": "10.0.0.1"})

    def test_returns_dict(self):
        proxy_list = [{"http": "127.0.0.1"}, {"https": "127.0.0.2"}]
        result = get_random_proxy(proxy_list)
        self.assertIsInstance(result, dict)

    def test_empty_list_raises(self):
        with self.assertRaises(IndexError):
            get_random_proxy([])

    def test_distribution_covers_all_proxies(self):
        proxy_list = [{"http": f"10.0.0.{i}"} for i in range(5)]
        seen = set()
        for _ in range(200):
            result = get_random_proxy(proxy_list)
            seen.add(result["http"])
        self.assertEqual(seen, {p["http"] for p in proxy_list},
                         "All proxies should be selected at least once over 200 draws")


if __name__ == "__main__":
    unittest.main()
