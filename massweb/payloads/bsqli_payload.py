from massweb.payloads.payload import Payload

class BSQLIPayload(Payload):

    def __init__(self, payload_str, payload_attributes, check_type_list = ["bsqli"]):
        
        super(BSQLIPayload, self).__init__(payload_str, check_type_list = check_type_list, payload_attributes = payload_attributes)
        if "truth" not in payload_attributes:
            raise Exception("A BSQLIPayload must have a truth attribute assigned to it, indicating the truth value of the payload for a SQL db")
        if payload_attributes["truth"] != True and payload_attributes["truth"] != False:
            raise Exception("The truth attribute assigned to the BSQLIPayload class must be True or False ")

if __name__ == "__main__":
    x = BSQLIPayload("blahblahblah", {"truth" : False})
    print x.payload_attributes