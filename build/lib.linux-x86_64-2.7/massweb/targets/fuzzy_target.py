from massweb.payloads.payload import Payload

class FuzzyTarget(object):

    def __eq__(self, other):
        return self.url == other.url and self.payload == other.payload and self.ttype == other.ttype

    def __hash__(self):
        return hash((self.url, self.payload, self.ttype))

    def __str__(self):
        return self.url

    def __init__(self, url, ttype = "get", payload = None):

        if type(payload) != Payload:
            raise Exception("payload must be of type Payload")

        self.url = url
        self.ttype = ttype
        self.payload = payload
        self.data = {}

    """
    def replace_param_value(url, param, replacement_string):
        '''Replace a parameter in a url with another string. Returns
        a fully reassembled url as a string.'''

        url_parsed = urlparse(url)
        query_dic = parse_qs(url_parsed.query)
        query_dic[param] = replacement_string

        #this incidentally will also automatically url-encode the payload (thanks urlencode!)
        query_reassembled = urlencode(query_dic, doseq = True)

        #3rd element is always the query, replace query with our own
        url_list_parsed = list(url_parsed)
        url_list_parsed[4] = query_reassembled
        url_parsed_q_replaced = tuple(url_list_parsed)
        url_reassembled = urlunparse(url_parsed_q_replaced)

        return url_reassembled
    """

if __name__ == "__main__":

    ft1 = FuzzyTarget("ddd", payload = Payload("ddd", check_type_list = ["ddd"]))
    ft2 = FuzzyTarget("ddd", payload = Payload("ddd", check_type_list = ["ddd"]))

    if ft1 == ft2:
        print "equal"

