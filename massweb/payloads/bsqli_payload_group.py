""" Blind SQL Injection (BSQLI) PayloadGroup type """
#FIXME: how does this handle add_payload?
#   Due: 3.2:
#       should this be a different class of object?
#           it seems to ditch all the major bits of PayloadGroup
#       should this have the same interface as PayloadGroup?
#       

from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.payload_group import PayloadGroup

class BSQLIPayloadGroup(PayloadGroup):
    """ Blind SQL Injection Payload type:
    contains multiple pairs of BSQLIPayloads"""

    #FIXME suggest this be made the same as the Payload object __init__ but with tuples containing true and false rather than independent args or have each BSQLIPayload contain both the true and false payloads (ref: "1 or n" concept)
    def __init__(self, true_payload, false_payload):
        """ 
        true_payload    BSQLIPayload for the true SQL statement
        false_payload   BSQLIPayload for the false SQL statement
        """
        if isinstance(true_payload, BSQLIPayload) and isinstance(false_payload, BSQLIPayload):
            pass
        else:
            raise TypeError("input payloads must be of type BSQLIPayload")
        #FIXME: maybe just negate this and skip the else?
        if true_payload.payload_attributes["truth"] == True and false_payload.payload_attributes["truth"] == False:
            pass
        else:
            raise ValueError("true_payload must have an truth attribute of True and false_payload must have a truth attribute of False")
        self.true_payload = true_payload
        self.false_payload = false_payload

"""
    payload_false = BSQLIPayload("dddd", {"truth" : False})
    payload_true = BSQLIPayload("ddd333d", {"truth" : True})
    bspg = BSQLIPayloadGroup(payload_true, payload_false)
""" 
