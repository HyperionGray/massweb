"""Tests for FuzzyTargetGroup bulk append helpers."""

import unittest

from massweb.targets.fuzzy_target_group import FuzzyTargetGroup


class TestFuzzyTargetGroup(unittest.TestCase):
    """Validate target-group convenience methods."""

    def test_add_targets_appends_in_order(self):
        group = FuzzyTargetGroup()
        group.add_targets(["first", "second", "third"])
        self.assertEqual(group.fuzzy_targets, ["first", "second", "third"])

    def test_add_targets_rejects_non_sequence_input(self):
        group = FuzzyTargetGroup()
        with self.assertRaises(TypeError):
            group.add_targets("not-a-sequence-of-targets")

    def test_add_targets_supports_tuple_input(self):
        group = FuzzyTargetGroup()
        group.add_targets(("a", "b"))
        self.assertEqual(group.fuzzy_targets, ["a", "b"])


if __name__ == "__main__":
    unittest.main()
