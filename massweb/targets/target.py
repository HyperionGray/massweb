class Target(object):

    def __eq__(self, other):
        return self.url == other.url and self.ttype == other.ttype

    def __hash__(self):
        return hash((self.url, self.ttype))

    def __unicode__(self):
        return self.url

    def __str__(self):
        return unicode(self).encode('utf-8', 'replace')

    def __init__(self, url, data = None, ttype = "get"):

        if not isinstance(url, unicode):
            print "exception"
            raise Exception("URL input must be unicode, not string")

        self.url = url
        self.ttype = ttype
        self.data = data

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

    t = Target("http://www.hyperiongray.com/")
    print unicode(t)
