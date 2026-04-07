""" Offline unit tests for massweb.mass_requests.mass_request.MassRequest """

import unittest

from massweb.mass_requests.mass_request import MassRequest, GET, POST
from massweb.targets.target import Target


class TestMassRequestInit(unittest.TestCase):

    def test_default_init(self):
        mr = MassRequest()
        self.assertEqual(mr.num_threads, 10)
        self.assertEqual(mr.time_per_url, 10)
        self.assertEqual(mr.request_timeout, 10)
        self.assertEqual(mr.proxy_list, [{}])
        self.assertIsNone(mr.requests_per_second)
        self.assertEqual(mr.results, [])
        self.assertEqual(mr.finished, [])
        self.assertEqual(mr.attempted, [])

    def test_custom_init(self):
        mr = MassRequest(num_threads=5, time_per_url=20, request_timeout=15,
                         proxy_list=[{"http": "127.0.0.1"}],
                         requests_per_second=2.0)
        self.assertEqual(mr.num_threads, 5)
        self.assertEqual(mr.time_per_url, 20)
        self.assertEqual(mr.request_timeout, 15)
        self.assertEqual(mr.proxy_list, [{"http": "127.0.0.1"}])
        self.assertEqual(mr.requests_per_second, 2.0)

    def test_invalid_requests_per_second_raises(self):
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=0)
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=-1)

    def test_proxy_list_defaults_to_empty_dict_list(self):
        mr = MassRequest(proxy_list=None)
        self.assertEqual(mr.proxy_list, [{}])


class TestMassRequestToTarget(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_str_url_becomes_target(self):
        t = self.mr.to_target("http://example.com/", GET)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")
        self.assertEqual(t.ttype, GET)

    def test_bytes_url_becomes_target(self):
        t = self.mr.to_target(b"http://example.com/", GET)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")

    def test_tuple_url_data_becomes_post_target(self):
        t = self.mr.to_target(("http://example.com/", {"key": "val"}), POST)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")
        self.assertEqual(t.data, {"key": "val"})
        self.assertEqual(t.ttype, POST)

    def test_list_url_data_becomes_target(self):
        t = self.mr.to_target(["http://example.com/", {"k": "v"}], POST)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")

    def test_target_passthrough(self):
        original = Target("http://example.com/", ttype=GET)
        t = self.mr.to_target(original, GET)
        self.assertIs(t, original)

    def test_invalid_tuple_length_raises(self):
        with self.assertRaises(ValueError):
            self.mr.to_target(("http://example.com/",), GET)

    def test_unsupported_type_raises(self):
        with self.assertRaises(TypeError):
            self.mr.to_target(12345, GET)


class TestMassRequestCheckMethodInput(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_valid_targets_returns_none(self):
        targets = [Target("http://a.com/"), Target("http://b.com/")]
        result = self.mr._check_method_input(targets, "targets", Target)
        self.assertIsNone(result)

    def test_empty_targets_returns_value_error(self):
        result = self.mr._check_method_input([], "targets", Target)
        self.assertIsInstance(result, ValueError)

    def test_wrong_type_returns_type_error(self):
        result = self.mr._check_method_input(["not_a_target"], "targets", Target)
        self.assertIsInstance(result, TypeError)


class TestMassRequestUrls(unittest.TestCase):

    def setUp(self):
        self.mr = MassRequest()

    def test_get_urls_empty_raises(self):
        with self.assertRaises(ValueError):
            self.mr.get_urls([])

    def test_get_urls_non_list_raises(self):
        with self.assertRaises(TypeError):
            self.mr.get_urls("http://example.com/")

    def test_post_urls_empty_raises(self):
        with self.assertRaises(ValueError):
            self.mr.post_urls([])

    def test_post_urls_non_list_raises(self):
        with self.assertRaises(TypeError):
            self.mr.post_urls("http://example.com/")


class TestMassRequestProperties(unittest.TestCase):

    def test_urls_attempted_and_finished(self):
        mr = MassRequest()
        t1 = Target("http://a.com/")
        t2 = Target("http://b.com/")
        mr.attempted = [t1, t2]
        mr.finished = [t1]
        self.assertEqual(mr.urls_attempted, ["http://a.com/", "http://b.com/"])
        self.assertEqual(mr.urls_finished, ["http://a.com/"])
        self.assertEqual(mr.targets_attempted, [t1, t2])
        self.assertEqual(mr.targets_finished, [t1])


if __name__ == "__main__":
    unittest.main()
