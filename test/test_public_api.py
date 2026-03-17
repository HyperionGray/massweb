import unittest

from massweb.masscrawler import MassCrawl, MassCrawler
from massweb.targets import CrawlTarget, FuzzyTargetGroup, Target


class TestFuzzyTargetGroupBulkAdd(unittest.TestCase):
    def test_add_targets_appends_values_in_order(self):
        group = FuzzyTargetGroup()
        first = object()
        second = object()
        group.add_targets([first, second])
        self.assertEqual(group.fuzzy_targets, [first, second])

    def test_add_targets_accepts_generator(self):
        group = FuzzyTargetGroup()
        values = (value for value in [1, 2, 3])
        group.add_targets(values)
        self.assertEqual(group.fuzzy_targets, [1, 2, 3])

    def test_add_targets_none_is_noop(self):
        group = FuzzyTargetGroup()
        group.add_targets(None)
        self.assertEqual(group.fuzzy_targets, [])

    def test_add_targets_rejects_non_iterable(self):
        group = FuzzyTargetGroup()
        self.assertRaises(TypeError, group.add_targets, 42)


class TestPublicExports(unittest.TestCase):
    def test_masscrawler_alias_is_available(self):
        crawler = MassCrawler()
        self.assertIsInstance(crawler, MassCrawl)

    def test_targets_exports_are_available(self):
        self.assertEqual(Target.__name__, "Target")
        self.assertTrue(issubclass(CrawlTarget, Target))
        self.assertEqual(FuzzyTargetGroup.__name__, "FuzzyTargetGroup")


if __name__ == "__main__":
    unittest.main()
