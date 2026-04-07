""" Unit tests for massweb.mass_requests.mass_request (offline / no network) """

import unittest

from massweb.mass_requests.mass_request import MassRequest, GET, POST
from massweb.targets.target import Target


class TestMassRequestInit(unittest.TestCase):

    def test_defaults(self):
        mr = MassRequest()
        self.assertEqual(mr.num_threads, 10)
        self.assertEqual(mr.time_per_url, 10)
        self.assertEqual(mr.request_timeout, 10)
        self.assertEqual(mr.proxy_list, [{}])
        self.assertIsNone(mr.requests_per_second)
        self.assertFalse(mr.hadoop_reporting)

    def test_custom_values(self):
        proxies = [{"http": "127.0.0.1:8080"}]
        mr = MassRequest(num_threads=5, time_per_url=3, request_timeout=2,
                         proxy_list=proxies, hadoop_reporting=True,
                         requests_per_second=10)
        self.assertEqual(mr.num_threads, 5)
        self.assertEqual(mr.time_per_url, 3)
        self.assertEqual(mr.request_timeout, 2)
        self.assertEqual(mr.proxy_list, proxies)
        self.assertTrue(mr.hadoop_reporting)
        self.assertEqual(mr.requests_per_second, 10)

    def test_invalid_requests_per_second_zero(self):
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=0)

    def test_invalid_requests_per_second_negative(self):
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=-5)

    def test_valid_requests_per_second_float(self):
        mr = MassRequest(requests_per_second=0.5)
        self.assertEqual(mr.requests_per_second, 0.5)


class TestMassRequestToTarget(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_str_url_get(self):
        target = self.mr.to_target("http://example.com/", GET)
        self.assertIsInstance(target, Target)
        self.assertEqual(target.url, "http://example.com/")
        self.assertEqual(target.ttype, GET)

    def test_bytes_url_get(self):
        target = self.mr.to_target(b"http://example.com/", GET)
        self.assertIsInstance(target, Target)
        self.assertEqual(target.url, "http://example.com/")

    def test_tuple_url_data_post(self):
        target = self.mr.to_target(("http://example.com/", {"key": "val"}), POST)
        self.assertIsInstance(target, Target)
        self.assertEqual(target.url, "http://example.com/")
        self.assertEqual(target.data, {"key": "val"})

    def test_list_url_data_post(self):
        target = self.mr.to_target(["http://example.com/", {"a": "b"}], POST)
        self.assertIsInstance(target, Target)
        self.assertEqual(target.url, "http://example.com/")

    def test_target_passthrough(self):
        t = Target("http://example.com/", ttype=GET)
        result = self.mr.to_target(t, GET)
        self.assertIs(result, t)

    def test_invalid_tuple_length(self):
        with self.assertRaises(ValueError):
            self.mr.to_target(("http://example.com/",), POST)

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            self.mr.to_target(12345, GET)


class TestMassRequestCheckMethodInput(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_valid_list_of_targets(self):
        targets = [Target("http://example.com/")]
        result = self.mr._check_method_input(targets, "targets", Target)
        self.assertIsNone(result)

    def test_empty_arg_returns_value_error(self):
        result = self.mr._check_method_input([], "targets", Target)
        self.assertIsInstance(result, ValueError)

    def test_none_arg_returns_value_error(self):
        result = self.mr._check_method_input(None, "targets", Target)
        self.assertIsInstance(result, ValueError)

    def test_wrong_item_type_returns_type_error(self):
        result = self.mr._check_method_input(["not-a-target"], "targets", Target)
        self.assertIsInstance(result, TypeError)


class TestMassRequestUrlsProperties(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_empty_urls_attempted(self):
        self.assertEqual(self.mr.urls_attempted, [])

    def test_empty_urls_finished(self):
        self.assertEqual(self.mr.urls_finished, [])

    def test_empty_targets_attempted(self):
        self.assertEqual(self.mr.targets_attempted, [])

    def test_empty_targets_finished(self):
        self.assertEqual(self.mr.targets_finished, [])


if __name__ == "__main__":
    unittest.main()
