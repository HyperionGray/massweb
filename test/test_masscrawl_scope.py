""" Offline unit tests for MassCrawl scope handling, deduplication,
    and domain utilities. """

import unittest

from massweb.masscrawler.masscrawl import MassCrawl
from massweb.targets.crawl_target import CrawlTarget


class TestMassCrawlDomainUtils(unittest.TestCase):

    def setUp(self):
        self.mc = MassCrawl(seeds=[])

    def test_get_domain_plain(self):
        self.assertEqual(self.mc.get_domain_from_url("http://example.com/page"), "example.com")

    def test_get_domain_with_port(self):
        self.assertEqual(self.mc.get_domain_from_url("http://example.com:8080/page"), "example.com")

    def test_get_domain_https(self):
        self.assertEqual(self.mc.get_domain_from_url("https://secure.example.com/"), "secure.example.com")

    def test_get_domain_subdomain(self):
        self.assertEqual(self.mc.get_domain_from_url("http://sub.example.com/path"), "sub.example.com")


class TestMassCrawlScope(unittest.TestCase):

    def setUp(self):
        self.mc = MassCrawl(seeds=[])

    def test_add_to_scope(self):
        self.mc.add_to_scope("example.com")
        self.assertIn("example.com", self.mc.domains)

    def test_add_to_scope_no_duplicates(self):
        self.mc.add_to_scope("example.com")
        self.mc.add_to_scope("example.com")
        self.assertEqual(self.mc.domains.count("example.com"), 1)

    def test_in_scope_true(self):
        self.mc.add_to_scope("example.com")
        self.assertTrue(self.mc.in_scope("http://example.com/path"))

    def test_in_scope_false(self):
        self.mc.add_to_scope("example.com")
        self.assertFalse(self.mc.in_scope("http://other.com/path"))

    def test_add_seeds_to_scope(self):
        mc = MassCrawl(seeds=["http://example.com/", "http://other.org/"])
        self.assertIn("example.com", mc.domains)
        self.assertIn("other.org", mc.domains)

    def test_in_scope_with_port_ignored(self):
        self.mc.add_to_scope("example.com")
        self.assertTrue(self.mc.in_scope("http://example.com:8080/path"))


class TestMassCrawlDeduplication(unittest.TestCase):

    def test_add_target_no_duplicates(self):
        mc = MassCrawl(seeds=[])
        ct = CrawlTarget("http://example.com/")
        mc.add_target(ct)
        mc.add_target(ct)
        self.assertEqual(len(mc.targets), 1)

    def test_dedupe_targets_removes_duplicates(self):
        mc = MassCrawl(seeds=[])
        ct1 = CrawlTarget("http://example.com/")
        ct2 = CrawlTarget("http://example.com/")
        # Force two entries with the same hash by bypassing add_target guard
        mc.targets = [ct1, ct2]
        mc.dedupe_targets()
        self.assertEqual(len(mc.targets), 1)

    def test_dedupe_targets_keeps_unique(self):
        mc = MassCrawl(seeds=[])
        ct1 = CrawlTarget("http://example.com/a")
        ct2 = CrawlTarget("http://example.com/b")
        mc.targets = [ct1, ct2]
        mc.dedupe_targets()
        self.assertEqual(len(mc.targets), 2)


class TestMassCrawlFilterByScope(unittest.TestCase):

    def test_filter_removes_out_of_scope(self):
        mc = MassCrawl(seeds=["http://example.com/"])
        in_scope = CrawlTarget("http://example.com/page")
        out_of_scope = CrawlTarget("http://attacker.com/page")
        mc.targets = [in_scope, out_of_scope]
        mc.filter_targets_by_scope()
        urls = [t.url for t in mc.targets]
        self.assertIn("http://example.com/page", urls)
        self.assertNotIn("http://attacker.com/page", urls)

    def test_filter_keeps_all_in_scope(self):
        mc = MassCrawl(seeds=["http://example.com/"])
        ct1 = CrawlTarget("http://example.com/a")
        ct2 = CrawlTarget("http://example.com/b")
        mc.targets = [ct1, ct2]
        mc.filter_targets_by_scope()
        self.assertEqual(len(mc.targets), 2)


if __name__ == "__main__":
    unittest.main()
