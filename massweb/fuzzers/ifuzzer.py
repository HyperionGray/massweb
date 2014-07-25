from massweb.payloads.payload import Payload
from massweb.targets.target import Target

class iFuzzer(object):

    def add_payload(self, payload):

        if type(payload) != Payload:
            raise Exception("payload must be of type Payload")

        self.payloads.append(payload)

    def add_payload_from_string(self, payload_str, check_type_list):

        payload = Payload(payload_str, check_type_list)
        self.payloads.append(payload)

    def add_target_from_url(self, url, data = None):

        target = Target(url, data = data)
        self.targets.append(target)

    def add_target(self, target):

        if type(target) != Target:
            raise Exception("target must be of type Target")

        self.targets.append(target)

    def generate_fuzzy_targets(self):
        raise Exception("Not Implemented Error")

    def fuzz(self):
        raise Exception("Not Implemented Error")
