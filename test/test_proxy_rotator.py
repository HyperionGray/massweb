import unittest

from massweb.proxy_rotator.proxy_rotate import get_random_proxy


class TestGetRandomProxy(unittest.TestCase):

    def test_returns_element_from_list(self):
        proxy_list = [{"http": "127.0.0.1"}, {"http": "127.0.0.2"}]
        result = get_random_proxy(proxy_list)
        self.assertIn(result, proxy_list)

    def test_single_entry_list(self):
        proxy_list = [{"http": "127.0.0.1"}]
        result = get_random_proxy(proxy_list)
        self.assertEqual(result, {"http": "127.0.0.1"})

    def test_returns_dict(self):
        proxy_list = [{"http": "10.0.0.1"}, {"https": "10.0.0.2"}]
        result = get_random_proxy(proxy_list)
        self.assertIsInstance(result, dict)

    def test_empty_list_raises(self):
        with self.assertRaises(IndexError):
            get_random_proxy([])


if __name__ == "__main__":
    unittest.main()
