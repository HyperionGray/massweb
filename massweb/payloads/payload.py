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
        if not isinstance(other, Payload):
            raise TypeError("Cannot compare Payload to %s" % type(other).__name__)
        return (self.payload_str == other.payload_str and
                self.check_type_list == other.check_type_list)

    def __hash__(self):
        """ Provides a hash of the payload and check types """
        return hash((self.payload_str, str(self.check_type_list)))

    def __str__(self):
        """ Returns just the payload string """
        return self.payload_str

    def __init__(self, payload_str, check_type_list=None, payload_attributes=None):
        """ Initialize a Payload object.

         payload_str        str representing the payload or the url/domain for the payload.
         check_type_list    list of types of checks to use this payload for. Default [].
         payload_attributes dict containg attributes to be passed to the Fuzzer. Default {}.
        """
        self.check_type_list = check_type_list if check_type_list is not None else []
        self.payload_str = payload_str
        self.payload_attributes = payload_attributes if payload_attributes is not None else {}
