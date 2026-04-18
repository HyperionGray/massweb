""" Unit tests for massweb.mass_requests.mass_request (no network I/O). """

import unittest

from massweb.mass_requests.mass_request import MassRequest, GET, POST
from massweb.targets.target import Target


class TestMassRequestInit(unittest.TestCase):
    """ Tests for MassRequest.__init__() """

    def test_default_construction(self):
        mr = MassRequest()
        self.assertEqual(mr.num_threads, 10)
        self.assertEqual(mr.time_per_url, 10)
        self.assertEqual(mr.request_timeout, 10)
        self.assertIsNone(mr.requests_per_second)
        self.assertEqual(mr.results, [])
        self.assertEqual(mr.finished, [])
        self.assertEqual(mr.attempted, [])

    def test_requests_per_second_positive(self):
        mr = MassRequest(requests_per_second=5)
        self.assertEqual(mr.requests_per_second, 5)

    def test_requests_per_second_zero_raises(self):
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=0)

    def test_requests_per_second_negative_raises(self):
        with self.assertRaises(ValueError):
            MassRequest(requests_per_second=-1)

    def test_proxy_list_default_is_empty_dict_list(self):
        mr = MassRequest()
        self.assertEqual(mr.proxy_list, [{}])

    def test_custom_proxy_list(self):
        proxies = [{"http": "http://127.0.0.1:8080"}]
        mr = MassRequest(proxy_list=proxies)
        self.assertEqual(mr.proxy_list, proxies)


class TestToTarget(unittest.TestCase):
    """ Tests for MassRequest.to_target() """

    def setUp(self):
        self.mr = MassRequest()

    def test_str_url_becomes_get_target(self):
        t = self.mr.to_target("http://example.com/", GET)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")
        self.assertEqual(t.ttype, GET)

    def test_bytes_url_decoded(self):
        t = self.mr.to_target(b"http://example.com/", GET)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")

    def test_tuple_url_and_data(self):
        t = self.mr.to_target(("http://example.com/", {"key": "val"}), POST)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")
        self.assertEqual(t.data, {"key": "val"})

    def test_list_url_and_data(self):
        t = self.mr.to_target(["http://example.com/", {"k": "v"}], POST)
        self.assertIsInstance(t, Target)
        self.assertEqual(t.url, "http://example.com/")

    def test_target_passthrough(self):
        original = Target("http://example.com/", ttype=GET)
        result = self.mr.to_target(original, GET)
        self.assertIs(result, original)

    def test_invalid_tuple_length_raises(self):
        with self.assertRaises(ValueError):
            self.mr.to_target(("http://example.com/",), POST)

    def test_unsupported_type_raises(self):
        with self.assertRaises(TypeError):
            self.mr.to_target(12345, GET)


class TestGetUrls(unittest.TestCase):
    """ Tests for MassRequest.get_urls() / post_urls() input validation. """

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


class TestListDiff(unittest.TestCase):
    """ Tests for MassRequest.list_diff() — no network required. """

    def test_timed_out_targets_added_to_results(self):
        mr = MassRequest()
        t1 = Target("http://a.example.com/", ttype=GET)
        t2 = Target("http://b.example.com/", ttype=GET)
        mr.attempted = [t1, t2]
        mr.finished = [t1]          # t2 was not finished → timeout
        mr.list_diff()
        timeout_urls = [r[0].url for r in mr.results if r[1] == "__PNK_THREAD_TIMEOUT"]
        self.assertIn("http://b.example.com/", timeout_urls)

    def test_no_timed_out_targets_produces_no_timeout_results(self):
        mr = MassRequest()
        t = Target("http://example.com/", ttype=GET)
        mr.attempted = [t]
        mr.finished = [t]
        mr.list_diff()
        timeout_results = [r for r in mr.results if r[1] == "__PNK_THREAD_TIMEOUT"]
        self.assertEqual(timeout_results, [])

    def test_clear_lists_empties_attempted_and_finished(self):
        mr = MassRequest()
        mr.attempted = [Target("http://example.com/", ttype=GET)]
        mr.finished = [Target("http://example.com/", ttype=GET)]
        mr.clear_lists()
        self.assertEqual(mr.attempted, [])
        self.assertEqual(mr.finished, [])


class TestUrlsProperties(unittest.TestCase):
    """ Tests for urls_attempted / urls_finished properties. """

    def test_urls_attempted_extracts_urls(self):
        mr = MassRequest()
        mr.attempted = [
            Target("http://a.example.com/", ttype=GET),
            Target("http://b.example.com/", ttype=GET),
        ]
        self.assertEqual(mr.urls_attempted, ["http://a.example.com/", "http://b.example.com/"])

    def test_urls_finished_extracts_urls(self):
        mr = MassRequest()
        mr.finished = [Target("http://done.example.com/", ttype=GET)]
        self.assertEqual(mr.urls_finished, ["http://done.example.com/"])


if __name__ == "__main__":
    unittest.main()
