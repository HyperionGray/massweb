import json
from urlparse import urlparse

class Result(object):

    def __str__(self):

        url_parsed = urlparse(str(self.fuzzy_target))
        if self.fuzzy_target.ttype == "get":
            to_ret = json.dumps({"url" : str(self.fuzzy_target), "results" : self.result_dic, "request_type" : "get"})

        if self.fuzzy_target.ttype == "post":
            to_ret = json.dumps({"url" : str(self.fuzzy_target), "data" : self.fuzzy_target.data, "results" : self.result_dic, "request_type" : "post"})


        return to_ret

    def __init__(self, fuzzy_target, result_dic = {}):

        self.fuzzy_target = fuzzy_target
        self.result_dic = result_dic
