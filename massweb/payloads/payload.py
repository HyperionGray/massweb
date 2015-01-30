""" Payload object type/prototype """

class Payload(object):
    """ Payload Object Protoype:

    This provides a common interface for various payloads.
    """

    def __eq__(self, other):
        """ Check if this Payload is equal to another,
        based on the payload string and the type of checks to be run.

        other is the Payload object to be compared to this Payload object.
        """
        #FIXME: add typeerror exception here. this shouldn't be comparing if the type is wrong
        return (self.payload_str == other.payload_str and
                other.check_type_list == other.check_type_list)

    def __hash__(self):
        """ Provides a hash of the payload and check types """
        return hash((self.payload_str, str(self.check_type_list)))

    def __str__(self):
        """ Returns just the payload string """
        return self.payload_str

    def __init__(self, payload_str, check_type_list=[], payload_attributes={}):
        """ Initialize a Payload object.

         payload_str        str representing the payload or the url/domain for the payload.
         check_type_list    list of types of checks to use this payload for. Default [].
         payload_attributes dict containg attributes to be passed to the Fuzzer. Default {}.
        """
        self.check_type_list = check_type_list
        self.payload_str = payload_str
        self.payload_attributes = payload_attributes

#FIXME: Move to a unittest
"""
def test__eq__(self):
    self.assertIsEqual(Payload("ddd", ["dddd"]), Payload("ddd", ["dddd"]))

"""
