""" """
#FIXME: comment all the things
class Payload(object):
    """ """

    def __eq__(self, other):
        """ """
        return (self.payload_str == other.payload_str and
                other.check_type_list == other.check_type_list)

    def __hash__(self):
        """ """
        return hash((self.payload_str, str(self.check_type_list)))

    def __str__(self):
        """ """
        return self.payload_str

    def __init__(self, payload_str, check_type_list=[], payload_attributes={}):
        """ """
        self.check_type_list = check_type_list
        self.payload_str = payload_str
        self.payload_attributes = payload_attributes

"""
def test__eq__(self):
    self.assertIsEqual(Payload("ddd", ["dddd"]), Payload("ddd", ["dddd"]))

"""
