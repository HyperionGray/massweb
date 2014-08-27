import json
from urlparse import urlparse

class Result(object):

    def __unicode__(self):

        url_parsed = urlparse(str(self.fuzzy_target))
        if self.fuzzy_target.ttype == "get":
            to_ret = json.dumps({"url" : unicode(self.fuzzy_target), "results" : self.result_dic, "request_type" : "get", "fuzzy_param" : self.fuzzy_target.fuzzy_param})

        if self.fuzzy_target.ttype == "post":
            to_ret = json.dumps({"url" : unicode(self.fuzzy_target), "data" : self.fuzzy_target.data, "results" : self.result_dic, "request_type" : "post", "fuzzy_param" : self.fuzzy_target.fuzzy_param})

        return to_ret        

    def __str__(self):

        return unicode(self).encode('utf-8', 'replace')

    def __init__(self, fuzzy_target, result_dic = {}):

        self.fuzzy_target = fuzzy_target
        self.result_dic = result_dic
