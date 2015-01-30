""" PayloadGroup type/prototype containing multiple Payload objects """


class PayloadGroup(object):
    """ PayloadGroup Class: groups of individual Payload objects. """

    def __init__(self, payloads, check_type_list=[]):
        """ Initialize a PayloadGroup
        This interface is kept similar to the interface for the Payload class.

        payloads        list of Payload objects.
        check_type_list list of types of checks to run using these Payloads. Default [].
        """
        self.payloads = payloads

    def add_payload(self, payload):
        """ Add a Payloadobject to this group.

        payload Payload object
        """
        self.payloads.append(payload)
