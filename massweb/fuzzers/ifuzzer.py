""" Fuzzer Prototype. """

from urlparse import parse_qs, urlparse, urlunparse
from urllib import urlencode

from massweb.fuzz_generators.url_generator import append_to_param, replace_param_value
from massweb.payloads.payload import Payload
from massweb.targets.target import Target


class iFuzzer(object):
    """ Prototype Fuzzer class.

    The following must be implemented in __init__()
    self.fuzzy_targets = []
    self.targets = []
    self.payloads = []
    self.mreq = MassRequest()
    """

    def add_payload(self, payload):
        """ Add a Payload object to the list of payloads.

        payload     Payload object.
        """
        if not isinstance(payload, Payload):
            raise TypeError("payload must be of type Payload")
        self.payloads.append(payload)

    def add_payload_from_string(self, payload_str, check_type_list):
        """ Add a Payload object created from the string provided and the types of checks to preform.
        
        payload_str         String representing the payload.
        check_type_list     list of strings identifying the types of checks to preform.
        """
        payload = Payload(payload_str, check_type_list)
        self.payloads.append(payload)

    def add_target_from_url(self, url, data=None):
        """ Add a target based on the URL and POAST request data.

        url     URL as a string.
        data    POST request data as s dict.
        """
        target = Target(url, data=data)
        self.targets.append(target)

    def add_target(self, target):
        """ Add Target object to list of targets.

        target  Target object.
        """
        if not isinstance(target, Target):
            raise TypeError("target must be of type Target")
        self.targets.append(target)

    #FIXME: maybe remove this to make bsqli and web fuzzers have a more uniform interface
    def generate_fuzzy_targets(self):
        """ Prototype for the method that generates a list of targets with the fuzzing data added. """
        pass

    def determine_posts_from_targets(self, dedupe=True):
        """ Add targets with POST requests to this Fuzzer's list of targets.
        dedupe Unused. Deduplicate targets if True. Default True.
        """
        self.mreq.get_post_requests_from_targets(self.targets)
        identified_posts = self.mreq.identified_post_requests
        # Dedupe posts if relevant
        identified_posts = list(set(identified_posts))
        for ip in identified_posts:
            if ip not in self.targets:
                self.targets.append(ip)

    def append_to_param(self, url, param, append_string):
        """ Replace a parameter in a url with another string.
        Return a fully reassembled url as a string.

        url                 URL to mangle as string.
        param               Parameter in url to replace the value of.
        append_string  String to append to the value of param in url with.
        """
        # for the purposes of maintaining consistent interfaces
        return append_to_param(url, param, append_string)
  
    def replace_param_value(self, url, param, replacement_string):
        """ Replace a parameter in a url with another string.
        Return a fully reassembled url as a string.

        url                 URL to mangle as string.
        param               Parameter in url to replace the value of.
        replacement_string  String to replace the value of param in url with.
        """
        # for the purposes of maintaining consistent interfaces
        return replace_param_value(url, param, replacement_string)


    def fuzz(self):
        """ Prototype for the primary entry point of Fuzzers. """
        raise NotImplementedError("fuzz() needs to be implemented in each child class.")


if __name__ == "__main__":
    aurl = "http://www.hyperiongray.com/?q=3234&&q=55555&x=33"
    aparam = "q"
    append_string = "added"
    aifuz = iFuzzer()
    append_result = aifuz.append_to_param(aurl, aparam, append_string)
    append_baseline = 'http://www.hyperiongray.com/?q=3234added&q=55555added&x=33'
    print("'%s' == '%s'" % (append_baseline, append_result), append_baseline == append_result)
    rurl = "http://www.hyperiongray.com/?q=3234&&q=55555&x=33"
    rparam = "q"
    replace_string = "replaced"
    rifuz = iFuzzer()
    replace_result = rifuz.replace_param_value(rurl, rparam, replace_string)
    replace_baseline = "http://www.hyperiongray.com/?q=replaced&q=replaced&x=33"
    print("'%s' == '%s'" % (replace_baseline, replace_result), replace_baseline == replace_result)

