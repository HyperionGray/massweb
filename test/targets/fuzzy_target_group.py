"""Tests for FuzzyTargetGroup."""

import unittest

from massweb.targets.fuzzy_target_group import FuzzyTargetGroup


class TestFuzzyTargetGroup(unittest.TestCase):
    """FuzzyTargetGroup behavior tests."""

    def test_init_defaults_to_empty_list(self):
        group = FuzzyTargetGroup()
        self.assertEqual(group.fuzzy_targets, [])

    def test_add_target_appends_single_item(self):
        group = FuzzyTargetGroup()
        target = object()
        group.add_target(target)
        self.assertEqual(group.fuzzy_targets, [target])

    def test_add_targets_appends_multiple_items_in_order(self):
        group = FuzzyTargetGroup()
        targets = [object(), object(), object()]
        group.add_targets(targets)
        self.assertEqual(group.fuzzy_targets, targets)

    def test_add_targets_rejects_none(self):
        group = FuzzyTargetGroup()
        with self.assertRaises(TypeError):
            group.add_targets(None)


if __name__ == "__main__":
    unittest.main()
