""" Offline regression tests for crawler scope handling in MassCrawl """

import unittest

from massweb.masscrawler.masscrawl import MassCrawl


class TestMassCrawlScopeHandling(unittest.TestCase):
    """Tests for in-scope/out-of-scope URL filtering without network access."""

    def setUp(self):
        self.crawler = MassCrawl(seeds=["http://example.com/start"])

    # ------------------------------------------------------------------
    # get_domain_from_url
    # ------------------------------------------------------------------

    def test_get_domain_simple(self):
        self.assertEqual(
            self.crawler.get_domain_from_url("http://example.com/path"),
            "example.com",
        )

    def test_get_domain_strips_port(self):
        self.assertEqual(
            self.crawler.get_domain_from_url("http://example.com:8080/path"),
            "example.com",
        )

    def test_get_domain_subdomain(self):
        self.assertEqual(
            self.crawler.get_domain_from_url("http://sub.example.com/page"),
            "sub.example.com",
        )

    def test_get_domain_https(self):
        self.assertEqual(
            self.crawler.get_domain_from_url("https://secure.example.com/"),
            "secure.example.com",
        )

    # ------------------------------------------------------------------
    # add_to_scope / in_scope
    # ------------------------------------------------------------------

    def test_seed_domain_is_in_scope(self):
        self.assertTrue(self.crawler.in_scope("http://example.com/other"))

    def test_different_domain_is_out_of_scope(self):
        self.assertFalse(self.crawler.in_scope("http://attacker.com/"))

    def test_add_to_scope_then_in_scope(self):
        self.crawler.add_to_scope("newdomain.org")
        self.assertTrue(self.crawler.in_scope("http://newdomain.org/page"))

    def test_add_to_scope_no_duplicate(self):
        before = len(self.crawler.domains)
        self.crawler.add_to_scope("example.com")
        self.assertEqual(len(self.crawler.domains), before)

    def test_add_to_scope_from_url(self):
        self.crawler.add_to_scope_from_url("http://another.com/some/path")
        self.assertTrue(self.crawler.in_scope("http://another.com/"))

    def test_subdomain_requires_explicit_scope(self):
        # Only exact domain match is considered in-scope
        self.assertFalse(self.crawler.in_scope("http://sub.example.com/"))

    def test_multiple_seeds_all_in_scope(self):
        crawler = MassCrawl(seeds=["http://site-a.com", "http://site-b.com"])
        self.assertTrue(crawler.in_scope("http://site-a.com/page"))
        self.assertTrue(crawler.in_scope("http://site-b.com/page"))
        self.assertFalse(crawler.in_scope("http://site-c.com/page"))

    # ------------------------------------------------------------------
    # filter_targets_by_scope
    # ------------------------------------------------------------------

    def test_filter_removes_out_of_scope_targets(self):
        from massweb.targets.crawl_target import CrawlTarget

        crawler = MassCrawl(seeds=["http://good.com/"])
        extra = CrawlTarget("http://evil.com/bad")
        crawler.add_target(extra)
        # Verify it was added
        urls = [t.url for t in crawler.targets]
        self.assertIn("http://evil.com/bad", urls)

        crawler.filter_targets_by_scope()

        urls_after = [t.url for t in crawler.targets]
        self.assertNotIn("http://evil.com/bad", urls_after)

    def test_filter_keeps_in_scope_targets(self):
        from massweb.targets.crawl_target import CrawlTarget

        crawler = MassCrawl(seeds=["http://good.com/"])
        in_scope = CrawlTarget("http://good.com/page")
        crawler.add_target(in_scope)
        crawler.filter_targets_by_scope()

        urls_after = [t.url for t in crawler.targets]
        self.assertIn("http://good.com/page", urls_after)


if __name__ == "__main__":
    unittest.main()
