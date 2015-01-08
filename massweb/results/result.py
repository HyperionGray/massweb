""" Result object type/prototype """

import json

class Result(object):
    """ Result type: encapsulates information relevant to the results
        of a test. """

    def __unicode__(self):
        """ Returns  this object in a json formatted string. """
        # Assuming: self.fuzzy_target.ttype == "get" or
        #  self.fuzzy_target.ttype == "post"
        to_ret = json.dumps({"url" : unicode(self.fuzzy_target),
                             "data" : self.fuzzy_target.data,
                             "results" : self.result_dic,
                             "request_type" : self.fuzzy_target.ttype,
                             "fuzzy_param" : self.fuzzy_target.fuzzy_param})
        return to_ret

    def __str__(self):
        """ Returns a utf-8 encoded string """
        return unicode(self).encode('utf-8', 'replace')

    def __init__(self, fuzzy_target, result_dic=None):
        """ Initialize a Result object.
        fuzzy_target    FuzzyTarget object.
        result_dic      dict containing keys of types of chercks and bool
                            values indicating success or failure. Default None.
        """
        self.fuzzy_target = fuzzy_target
        self.result_dic = result_dic or {}
