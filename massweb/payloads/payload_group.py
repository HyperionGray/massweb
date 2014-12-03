from massweb.payloads.payload import Payload

class PayloadGroup(object):

    def __init__(self, payloads, check_type_list = []):
        
        self.payloads = payloads
    
    def add_payload(self, payload):
        
        self.payloads.append(payload)