""" FuzzyTarget type/prototype """

import unittest

from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.payloads.payload import Payload


class TestFuzzyTarget(unittest.TestCase):
    """ Target type for targets with their fuzzing precursors."""

    def test_eq(self):
        # fail if >> not isinstance(other, FuzzyTarget):
        # self.assertRaise(TypeError)
        # fail if not:
        #    self.url == other.url
        #    self.payload == other.payload
        #    self.ttype == other.ttype
        pass

    def test_hash(self):
        # see if fail if any of the values below are not normal
        # hash((self.url, self.payload, self.ttype, str(self.data)))
        pass

    def test_init(self):
        # fail if not:
        #   isinstance(payload, Payload):
        #       self.assertRaise(TypeError)
        #   isinstance(unfuzzed_url, unicode):
        #       self.assertRaise(TypeError)
        # verify
        #   self.payload = payload
        #   self.fuzzy_param = fuzzy_param
        #   self.unfuzzed_url = unfuzzed_url
        #   self.unfuzzed_data = unfuzzed_data
        #   self.unfuzzed_target = Target(unfuzzed_url, unfuzzed_data,
        #                                 ttype=ttype)
        pass

    def test_full(self):
        ft1 = FuzzyTarget(u"url", u"unfuzzed_url", "fuzzy_param",
                          payload=Payload(u"url", check_type_list=["mxi"]))
        ft2 = FuzzyTarget(u"url", u"unfuzzed_url", "fuzzy_param",
                          payload=Payload(u"url", check_type_list=["mxi"]))
        self.assertEqual(ft1, ft2)


if __name__ == '__main__':
    unittest.main()
