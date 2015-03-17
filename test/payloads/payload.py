""" Payload object type/prototype """

import unittest

from massweb.payloads.payload import Payload

class TestPayload(unittest.TestCase):
    """ Payload Object Protoype:

    This provides a common interface for various payloads.
    """

    def test_eq(self, other):
        # fail if not:
        #   self.payload_str == other.payload_str and
        #   self.check_type_list == other.check_type_list
        pass

    def test_hash(self):
        # verify output given relevant inputs
        # hash((self.payload_str, str(self.check_type_list)))
        pass

    def test_str(self):
        # verify output only
        # self.payload_str
        pass

    def test_init(self):
        # (payload_str, check_type_list=[], payload_attributes={})
        # verify:
        #   self.check_type_list = check_type_list
        #   self.payload_str = payload_str
        #   self.payload_attributes = payload_attributes
        pass

    def test_full(self):
        self.assertEqual(Payload("ddd", ["dddd"]), Payload("ddd", ["dddd"]))
