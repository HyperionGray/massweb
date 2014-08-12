from massweb.payloads.payload import Payload
from massweb.targets.target import Target

class FuzzyTarget(Target):

    def __eq__(self, other):
        return self.url == other.url and self.payload == other.payload and self.ttype == other.ttype

    def __hash__(self):
        return hash((self.url, self.payload, self.ttype))

    def __init__(self, url, ttype = "get", data = None, payload = None):

        if type(payload) != Payload:
            raise Exception("payload must be of type Payload")

        super(FuzzyTarget, self).__init__(url, data = data, ttype = ttype)
        self.payload = payload

if __name__ == "__main__":

    ft1 = FuzzyTarget("ddd", payload = Payload("ddd", check_type_list = ["ddd"]))
    ft2 = FuzzyTarget("ddd", payload = Payload("ddd", check_type_list = ["ddd"]))

    if ft1 == ft2:
        print "equal"

    print ft1.payload
    print ft1.url
    print ft1
