""" Fuzzer Prototype. """

import logging

from massweb.fuzz_generators.url_generator import append_to_param
from massweb.fuzz_generators.url_generator import replace_param_value
from massweb.payloads.payload import Payload
from massweb.targets.target import Target


logger = logging.getLogger("iFuzzer")


class iFuzzer(object):
    """ Prototype Fuzzer class. """

    def __init__(self):
        """ Prototype __init__ method. """
        self.fuzzy_targets = []
        self.targets = []
        self.payloads = []
        self.mreq = None

    def add_payload(self, payload):
        """ Add a Payload object to the list of payloads.

        payload     Payload object.
        """
        if not isinstance(payload, Payload):
            raise TypeError("payload must be of type Payload")
        self.payloads.append(payload)

    def add_payload_from_string(self, payload_str, check_type_list):
        """ Add a Payload generated from a string.

        Add a Payload object created from the string provided and the types
        of checks to preform.

        payload_str         String representing the payload.
        check_type_list     list of strings identifying the types of checks to
                                preform.
        """
        payload = Payload(payload_str, check_type_list)
        self.add_payload(payload)

    def add_target_from_url(self, url, data=None):
        """ Add a target based on the URL and POAST request data.

        url     URL as a string.
        data    POST request data as s dict.
        """
        target = Target(url, data=data)
        self.add_target(target)

    def add_target(self, target):
        """ Add Target object to list of targets.

        target  Target object.
        """
        if not isinstance(target, Target):
            raise TypeError("target must be of type Target")
        if target not in self.targets:
            self.targets.append(target)

    #FIXME: maybe remove this to make bsqli and web fuzzers have a more uniform interface
    def generate_fuzzy_targets(self):
        """ Prototype for the method that generates a list of targets with the fuzzing data added. """
        pass

    def determine_posts_from_targets(self, depreciated=None):
        """ Add targets with POST requests to this Fuzzer's list of targets.

        depreciated     Interface placeholder for dedupe which was unused.
        """
        if depreciated is False or depreciated:
            logger.warn("The dedupe argument for determine_posts_from_targets"
                        " is depreciated.")
        identified_posts = self.identify_posts()
        self.append_targets(identified_posts)

    def append_targets(self, targets):
        """ Append a list of Target objects to self.targets. """
        for target in targets:
            self.add_target(target)

    def identify_posts(self):
        """ Return a list of POST Targets. """
        self.mreq.get_post_requests_from_targets(self.targets)
        identified_posts = self.mreq.identified_post_requests
        deduped_posts = list(set(identified_posts))
        return deduped_posts

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
        raise NotImplementedError("fuzz() needs to be implemented in each "
                                  "child class.")
