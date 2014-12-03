from massweb.payloads.payload import Payload
from massweb.targets.target import Target
from urlparse import parse_qs
from urlparse import urlparse
from urlparse import urlunparse
from urllib import urlencode

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
        pass

    def replace_param_value(self, url, param, replacement_string):
        '''Replace a parameter in a url with another string. Returns
        a fully reassembled url as a string.'''

        url_parsed = urlparse(url)
        query_dic = parse_qs(url_parsed.query)
        #!potential bug here? This expects a list, but seems to work        
        query_dic[param] = [replacement_string for x in query_dic[param]]

        #this incidentally will also automatically url-encode the payload (thanks urlencode!)
        #!might cause some incorrect query params and keys with utf-8, needs more testing
        str_query_dic = {}
        for k, v in query_dic.iteritems():
            str_query_dic[unicode(k).encode('utf-8', 'replace')] = [x.encode('utf-8', 'replace') for x in v]

        query_reassembled = urlencode(str_query_dic, doseq = True)

        #3rd element is always the query, replace query with our own
        url_list_parsed = list(url_parsed)
        url_list_parsed[4] = query_reassembled
        url_parsed_q_replaced = tuple(url_list_parsed)
        url_reassembled = urlunparse(url_parsed_q_replaced)

        return url_reassembled
    
    def append_to_param(self, url, param, append_string):
        '''Append a value to a parameter'''

        url_parsed = urlparse(url)
        query_dic = parse_qs(url_parsed.query)
        #!potential bug here? This expects a list, but seems to work        
        query_dic[param] = [x + append_string for x in query_dic[param]]

        #this incidentally will also automatically url-encode the payload (thanks urlencode!)
        #!might cause some incorrect query params and keys with utf-8, needs more testing
        str_query_dic = {}
        for k, v in query_dic.iteritems():
            str_query_dic[unicode(k).encode('utf-8', 'replace')] = [x.encode('utf-8', 'replace') for x in v]

        query_reassembled = urlencode(str_query_dic, doseq = True)

        #3rd element is always the query, replace query with our own
        url_list_parsed = list(url_parsed)
        url_list_parsed[4] = query_reassembled
        url_parsed_q_replaced = tuple(url_list_parsed)
        url_reassembled = urlunparse(url_parsed_q_replaced)

        return url_reassembled

    def determine_posts_from_targets(self, dedupe = True):

        self.mreq.get_post_requests_from_targets(self.targets)
        identified_posts = self.mreq.identified_post_requests            

        #dedupe posts if relevant
        identified_posts = list(set(identified_posts))

        for ip in identified_posts:
            if ip not in self.targets:
                self.targets.append(ip)

    def fuzz(self):
        raise Exception("Not Implemented Error")

if __name__ == "__main__":
    url = "http://www.hyperiongray.com/?q=3234&&q=55555&x=33"
    param = "q"
    append_string= " AND 1=1"
    ifuz = iFuzzer()
    print ifuz.append_to_param(url, param, append_string)

    
