"""Tests for FuzzyTargetGroup bulk-add behavior."""

import unittest

from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.fuzzy_target_group import FuzzyTargetGroup


def _fake_fuzzy_target():
    """Create a FuzzyTarget instance without invoking legacy init checks."""
    return object.__new__(FuzzyTarget)


class TestFuzzyTargetGroup(unittest.TestCase):
    """Coverage for add_target and add_targets validation."""

    def test_add_target_rejects_invalid_item(self):
        group = FuzzyTargetGroup()
        with self.assertRaises(TypeError):
            group.add_target("not-a-target")

    def test_add_targets_appends_in_order(self):
        group = FuzzyTargetGroup()
        first = _fake_fuzzy_target()
        second = _fake_fuzzy_target()

        group.add_targets([first, second])

        self.assertEqual([first, second], group.fuzzy_targets)

    def test_add_targets_rejects_non_iterable(self):
        group = FuzzyTargetGroup()
        with self.assertRaises(TypeError):
            group.add_targets(42)

    def test_add_targets_is_atomic_when_input_has_invalid_type(self):
        group = FuzzyTargetGroup()
        valid_target = _fake_fuzzy_target()

        with self.assertRaises(TypeError):
            group.add_targets([valid_target, "bad-target-type"])

        self.assertEqual([], group.fuzzy_targets)


if __name__ == "__main__":
    unittest.main()
