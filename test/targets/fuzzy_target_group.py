"""Tests for FuzzyTargetGroup."""

import unittest

from massweb.targets.fuzzy_target_group import FuzzyTargetGroup


class TestFuzzyTargetGroup(unittest.TestCase):

    def test_add_target(self):
        group = FuzzyTargetGroup()
        group.add_target("target-1")
        self.assertEqual(group.fuzzy_targets, ["target-1"])

    def test_add_targets_returns_added_count(self):
        group = FuzzyTargetGroup()
        added = group.add_targets(["t1", "t2", "t3"])
        self.assertEqual(added, 3)
        self.assertEqual(group.fuzzy_targets, ["t1", "t2", "t3"])

    def test_add_targets_with_dedupe_skips_existing_items(self):
        group = FuzzyTargetGroup(["existing"])
        added = group.add_targets(["existing", "new"], dedupe=True)
        self.assertEqual(added, 1)
        self.assertEqual(group.fuzzy_targets, ["existing", "new"])

    def test_add_targets_none_raises_type_error(self):
        group = FuzzyTargetGroup()
        self.assertRaises(TypeError, group.add_targets, None)

    def test_add_targets_non_iterable_raises_type_error(self):
        group = FuzzyTargetGroup()
        self.assertRaises(TypeError, group.add_targets, 1)


if __name__ == '__main__':
    unittest.main()
