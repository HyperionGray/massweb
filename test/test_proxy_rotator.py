""" Unit tests for massweb.proxy_rotator.proxy_rotate """

import unittest

from massweb.proxy_rotator.proxy_rotate import get_random_proxy


class TestGetRandomProxy(unittest.TestCase):
    """ Tests for get_random_proxy() """

    def test_returns_item_from_list(self):
        """ Result must be one of the supplied proxies. """
        proxy_list = [
            {"http": "http://127.0.0.1:8080"},
            {"http": "http://127.0.0.2:8080"},
            {"http": "http://127.0.0.3:8080"},
        ]
        result = get_random_proxy(proxy_list)
        self.assertIn(result, proxy_list)

    def test_single_proxy_always_returned(self):
        """ A list with one entry should always return that entry. """
        proxy_list = [{"http": "http://127.0.0.1:8080"}]
        for _ in range(10):
            result = get_random_proxy(proxy_list)
            self.assertEqual(result, proxy_list[0])

    def test_returns_dict(self):
        """ Returned proxy should be a dict (requests-compatible proxy map). """
        proxy_list = [{"http": "http://proxy.example.com:3128"}]
        result = get_random_proxy(proxy_list)
        self.assertIsInstance(result, dict)

    def test_coverage_over_multiple_calls(self):
        """ Over many calls every proxy in the list should appear at least once.
        This is probabilistic; the list is small enough that failure would be
        astronomically unlikely with 1000 iterations.
        """
        proxy_list = [
            {"http": "http://127.0.0.1:8080"},
            {"http": "http://127.0.0.2:8080"},
        ]
        seen = set()
        for _ in range(1000):
            result = get_random_proxy(proxy_list)
            seen.add(result["http"])
        self.assertEqual(seen, {"http://127.0.0.1:8080", "http://127.0.0.2:8080"})

    def test_empty_list_raises(self):
        """ get_random_proxy with an empty list should raise IndexError (random.choice behaviour). """
        with self.assertRaises(IndexError):
            get_random_proxy([])


if __name__ == "__main__":
    unittest.main()
