""" """


class PayloadGroup(object):
    """ PayloadGroup Class: groups of individual Payload objects"""

    def __init__(self, payloads, check_type_list = []):
        """ FIXME Fill out this docstring
        payloads    ?list? of payload objects.
        check_type_list list of types of checks to run. Default [].
        """
        self.payloads = payloads

    def add_payload(self, payload):
        """ Add a Payloadobject to this group.
        payload Payload object
        """
        self.payloads.append(payload)
