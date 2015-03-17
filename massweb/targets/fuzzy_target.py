""" FuzzyTarget type/prototype """

from massweb.payloads.payload import Payload
from massweb.targets.target import Target

class FuzzyTarget(Target):
    """ Target type for targets with their fuzzing precursors."""

    def __eq__(self, other):
        """ Test whether this object and another FuzzyTarget object are equal
            based on the URL, payload, and request type. """
        if not isinstance(other, FuzzyTarget):
            raise TypeError("Must provide FuzzyTarget object for comparison.")
        return (self.url == other.url and
                self.payload == other.payload and
                self.ttype == other.ttype)

    def __hash__(self):
        """ Return a has of the URL, payload, request type, and ?data?. """
        return hash((self.url, self.payload, self.ttype, str(self.data)))

    def __init__(self, url, unfuzzed_url,
                 fuzzy_param, ttype="get",
                 data=None, payload=None,
                 unfuzzed_data=None):
        """
         url            str of location of the target.
         unfuzzed_url   str of the URL with the fuzzing data removed.
         fuzzy_param    dict of parameters to pass via the HTTP request body.
         ttype          HTTP request type. Default "get".
         data           dict of parameters to pass via the POST request body.
                            Default None.
         payload        Payload object containing. Default None.
         unfuzzed_data  dict of parameters to be passed to the unfuzzed Target
                            object (Target.data). Default None.
        """
        if not isinstance(payload, Payload):
            raise TypeError("payload must be of type Payload")
        if not isinstance(unfuzzed_url, unicode):
            raise TypeError("Unfuzzed URL input must be unicode, not string")
        super(FuzzyTarget, self).__init__(url, data=data, ttype=ttype)
        self.payload = payload
        self.fuzzy_param = fuzzy_param
        self.unfuzzed_url = unfuzzed_url
        self.unfuzzed_data = unfuzzed_data
        self.unfuzzed_target = Target(unfuzzed_url, unfuzzed_data, ttype=ttype)
