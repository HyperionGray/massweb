from massweb.payloads.payload import Payload
from massweb.targets.target import Target

class FuzzyTarget(Target):

    def __eq__(self, other):
        return self.url == other.url and self.payload == other.payload and self.ttype == other.ttype

    def __hash__(self):
        return hash((self.url, self.payload, self.ttype, str(self.data)))

    def __init__(self, url, unfuzzed_url, fuzzy_param, ttype = "get", data = None, payload = None, unfuzzed_data = None):

        if not isinstance(payload, Payload):
            raise Exception("payload must be of type Payload")

        if not isinstance(unfuzzed_url, unicode):
            print "exception"
            raise Exception("Unfuzzed URL input must be unicode, not string")

        super(FuzzyTarget, self).__init__(url, data = data, ttype = ttype)
        self.payload = payload
        self.fuzzy_param = fuzzy_param
        self.unfuzzed_url = unfuzzed_url
        self.unfuzzed_data = unfuzzed_data
        self.unfuzzed_target = Target(unfuzzed_url, unfuzzed_data, ttype = ttype)

if __name__ == "__main__":

    ft1 = FuzzyTarget(u"ddd", "dd", "dd", payload = Payload("ddd", check_type_list = ["ddd"]))
    ft2 = FuzzyTarget(u"ddd", "dd", payload = Payload("ddd", check_type_list = ["ddd"]))

    if ft1 == ft2:
        print "equal"

    print ft1.payload
    print ft1.url
    print ft1
