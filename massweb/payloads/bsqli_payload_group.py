from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.payload_group import PayloadGroup

class BSQLIPayloadGroup(PayloadGroup):

    def __init__(self, true_payload, false_payload):

        if isinstance(true_payload, BSQLIPayload) and isinstance(false_payload, BSQLIPayload):
            pass
        
        else:
            raise Exception("input payloads must be of type BSQLIPayload")

        if true_payload.payload_attributes["truth"] == True and false_payload.payload_attributes["truth"] == False:
            pass
        else:
            raise Exception("true_payload must have an truth attribute of True and false_payload must have a truth attribute of False")

        self.true_payload = true_payload
        self.false_payload = false_payload

if __name__ == "__main__":

    payload_true = BSQLIPayload("dddd", {"truth" : False})
    payload_true = BSQLIPayload("ddd333d", {"truth" : True})
    bspg = BSQLIPayloadGroup()