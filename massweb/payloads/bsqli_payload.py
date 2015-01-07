""" """
from massweb.payloads.payload import Payload

class BSQLIPayload(Payload):
    """ Blind SQL Injection Payload module """

    def __init__(self, payload_str, payload_attributes,
                 check_type_list=["bsqli"]):
        """
        payload_str str containing the payload.
        payload_attributes ?dict? of attributes of ___. Requires key 'truth' of type bool.
        check_type_list list of ways this should be checked. Default ["bsqli"].
        """
        super(BSQLIPayload, self).__init__(payload_str,
                                           check_type_list=check_type_list,
                                           payload_attributes=payload_attributes
                                          )
        if "truth" not in payload_attributes:
            raise KeyError("A BSQLIPayload must have a truth attribute assigned to it, indicating the truth value of the payload for a SQL db")
        if (payload_attributes["truth"] != True and
            payload_attributes["truth"] != False):
            raise TypeError("The truth attribute assigned to the BSQLIPayload class must be True or False ")

"""
def test_payload_attributes(self):
    self.assertIsEqual(BSQLIPayload("blahblahblah", {"truth" : False}).payload_attributes, expected_attributes)
"""
