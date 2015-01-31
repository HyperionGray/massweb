"""  Blind SQL injection fuzzer. """

from __future__ import division
import sys
import codecs
import logging
from urlparse import urlparse, parse_qs

from requests import Response
from requests.exceptions import HTTPError

from massweb.fuzzers.ifuzzer import iFuzzer

from massweb.mass_requests.mass_request import MassRequest

from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.bsqli_payload_group import BSQLIPayloadGroup

from massweb.results.result import Result

from massweb.targets.target import Target
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.fuzzy_target_group import FuzzyTargetGroup

# Setup loger
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('BSQLIFuzzer')
logger.setLevel(logging.INFO)

sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

class BSQLiFuzzer(iFuzzer):
    """ Blined SQL Injection Fuzzer class """

    def __init__(self, targets, bsqli_payload_groups = [], num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}], hadoop_reporting = False, payload_groups = []):
        """ Initialize this fuzzer.
        targets                 list of Target objects to fuzz.
        bsqli_payload_groups    list of BSQLiPayload groups. Default [].
        num_threads             Number of threads/processes torun for this fuzzer. Default 10.
        time_per_url            Time in seconds to spend on each target. Default 10.
        request_timeout         Time in seconds to wait beofre giving up on a connection. Defaut 10.
        proxy_list              list of proxies specified as a dict.
        hadoop_reporting        bool specifying whether to output messages for hadoop. Default False.
        payload_groups          Unused.
        """
        # do this because we may need to create more MassRequest objects in
        #  checks (like bsqli), needs to be configured the same
        self.mreq_config_dict = {"num_threads" : num_threads,
                "time_per_url" : time_per_url,
                "request_timeout" : request_timeout,
                "proxy_list" : proxy_list,
                "hadoop_reporting" : hadoop_reporting}
        self.mreq = MassRequest(**self.mreq_config_dict)
        self.allowed_variance = 0.2
        self.targets = targets
        self.payload_groups = payload_groups
        self.determine_posts_from_targets()
        self.stable_targets = []
        self.unstable_targets = []
        self.hadoop_reporting = hadoop_reporting
        if self.hadoop_reporting:
            logger.info("Hadoop reporting set in fuzzer")
        self.bsqli_payload_groups = bsqli_payload_groups
        self.fuzzy_target_groups = []
        for target in targets:
            try:
                max_content_length_variance = self.__check_url_stability(target)
                if max_content_length_variance > self.allowed_variance:
                    if hadoop_reporting:
                        logger.info(u"Found unstable target %s",
                                    unicode(target))
                    self.unstable_targets.append(target)
                else:
                    logger.info(u"Found stable target %s", unicode(target))
                    self.stable_targets.append(target)
            except:
                if self.hadoop_reporting:
                    logger.info(u"Found unstable target %s due to exception:",
                                unicode(target))
                self.unstable_targets.append(target)

    def __get_first_successful_response(self, results):
        """ Grab the first successful request.

        results     MassRequest.results.
        return      tuple of requests index (int) and requests.Response from that result.
        """
        for index, result in enumerate(results):
            target, response = result[0], result[1]
            if isinstance(response, Response):
                try:
                    response.raise_for_status()
                    if not response.content:
                        continue
                except HTTPError as exce:
                    continue
                return index, response
        return None, None

    def __check_url_stability(self, target, set_size = 10, successful_compares_required = 6):
        """ Check the stability of the output from a target.

        target      Target object.
        set_size    The number of times to request target. Default 10.
        successful_compares_required    Minimum number of time the page must be the same/similar. Default 6.
        """
        if self.hadoop_reporting:
            logger.info(u"Determining stability for %s", unicode(target))
        mreq = MassRequest(**self.mreq_config_dict)
        targets = [target]
        for _ in range(0, set_size):
            targets.append(target)
        mreq.request_targets(targets)
        baseline_element_used, baseline_response = self.__get_first_successful_response(mreq.results)
        if not baseline_response:
            raise ValueError("Didn't get a successful response from the URL, can't determine stability")
        # remove baseline element
        del mreq.results[baseline_element_used]
        content_length_variance = []
        for r in mreq.results:
            target, response = r[0], r[1]
            if not isinstance(response, Response):
                continue
            content_length_variance.append(((1 - len(response.content)/len(baseline_response.content)) * 100))
        if len(content_length_variance) < successful_compares_required:
            raise ValueError("Didn't get enough successful compares to determine stability")
        max_content_length_variance = abs(max(content_length_variance))
        return max_content_length_variance

    def __build_get_fuzzy_target_group_from_payload_group(self, target, bsqli_payload_group):
        """ Build a fuzzy-wuzzy target group from a PayloadGroup for GET requests.

        target                  Target object.
        bsqli_payload_group     BSQLiPayloadGroup object.
        """
        url = target.url
        parsed_url = urlparse(url)
        parsed_url_query = parsed_url.query
        url_q_dic = parse_qs(parsed_url_query)
        #FIXME: Investigate this -> i have no idea why an empty list has to be called to reinstantiate this object properly?
        fuzzy_target_groups = []
        for query_param, query_val in url_q_dic.iteritems():
            ftg = FuzzyTargetGroup()
            true_fuzzy_url = (self.append_to_param(url, query_param, str(bsqli_payload_group.true_payload)))
            true_fuzzy_target = FuzzyTarget(true_fuzzy_url, url, query_param, "get", payload = bsqli_payload_group.true_payload)
            ftg.add_target(true_fuzzy_target)
            false_fuzzy_url = (self.append_to_param(url, query_param, str(bsqli_payload_group.false_payload)))
            false_fuzzy_target = FuzzyTarget(false_fuzzy_url, url, query_param, "get", payload = bsqli_payload_group.false_payload)
            ftg.add_target(false_fuzzy_target)
            fuzzy_target_groups.append(ftg)
        return fuzzy_target_groups

    def __build_post_fuzzy_target_group_from_payload_group(self, target, bsqli_payload_group):
        """ Build a fuzzy-wuzzy target group from a PayloadGroup for POST requests.

        target                  Target object.
        bsqli_payload_group     BSQLiPayloadGroup object.
        """
        url = target.url
        post_keys = target.data.keys()
        #FIXME: Investigate why. !i have no idea why an empty list has to be called to reinstantiate this object properly?
        #  appears to be missing the self prefix and is defined in the method below
        fuzzy_target_groups = []
        for key in post_keys:
            ftg = FuzzyTargetGroup()
            true_payload = bsqli_payload_group.true_payload
            data_copy = target.data.copy()
            data_copy[key] = data_copy[key] + str(true_payload)
            fuzzy_target = FuzzyTarget(url, url, key, "post", data = data_copy.copy(), payload = true_payload, unfuzzed_data = target.data)
            ftg.add_target(fuzzy_target)
            false_payload = bsqli_payload_group.false_payload
            data_copy = target.data.copy()
            data_copy[key] = data_copy[key] + str(false_payload)
            fuzzy_target = FuzzyTarget(url, url, key, "post", data = data_copy.copy(), payload = false_payload, unfuzzed_data = target.data)
            ftg.add_target(fuzzy_target)
            fuzzy_target_groups.append(ftg)
        return fuzzy_target_groups

    def __build_fuzzy_target_groups(self):
        """ Build fuzzy groups of targets. 

        returns     list of Target objects with fuzzing data.
        """
        #clear out the target groups to avoid overlap
        self.fuzzy_target_groups = []
        if not self.bsqli_payload_groups:
            raise ValueError("bsqli_payload_groups is empty")
        for bsqli_payload_group in self.bsqli_payload_groups:
            if not self.targets:
                raise ValueError("targets is empty.")
            for target in self.targets:
                #FIXME: no need to hold these in local variables. they can be appended to self.fuzzy_target_groups directly
                if target.ttype == "get":
                    ftgs = self.__build_get_fuzzy_target_group_from_payload_group(target, bsqli_payload_group)
                elif target.ttype == "post":
                    ftgs = self.__build_post_fuzzy_target_group_from_payload_group(target, bsqli_payload_group)
                for ftg in ftgs:
                    self.fuzzy_target_groups.append(ftg)
        if not self.fuzzy_target_groups:
            raise ValueError("No fuzzy_target_groups created from: %s", ','.join([str(x) for x in self.targets]))

    def request_target_group(self, fuzzy_target_group):
        """ Fire off the fuzzies ...

        fuzzy_target_group  Group of Targets with fuzzing data added (the fuzzies).
        returns             the resulting MassRequest.results.
        """
        #FIXME: should this be self.mreq?
        mreq = MassRequest(**self.mreq_config_dict)
        mreq.request_targets(fuzzy_target_group.fuzzy_targets)
        return mreq.results

    def check_for_bsqli(self, fuzzy_target_group):
        """ Check a group of Target objects for evidence of Blind SQL injection vulnerabilities,

        fuzzy_target_group  list of Target objects with fuzzing data.
        returns             bool. True if vulnerability is present, False if not.
        """
        if self.hadoop_reporting:
            logger.info("Checking for BlindSQL in %s", fuzzy_target_group.fuzzy_targets[0].unfuzzed_url)
        request_results = self.request_target_group(fuzzy_target_group)
        for request_result in request_results:
            fuzzy_target, response = request_result
            if fuzzy_target.payload.payload_attributes["truth"] == True:
                true_target, true_response = fuzzy_target, response
            elif fuzzy_target.payload.payload_attributes["truth"] == False:
                false_target, false_response = fuzzy_target, response
            else:
                raise AttributeError("BSQLI target doesn't have truth attribute")
        # Check to see if we got both true and false request back succesfully
        try:
            true_response.raise_for_status()
            false_response.raise_for_status()
        except HTTPError as exce:
            logger.debug(exce, exc_info=True)
            raise HTTPError("Either the true or the false request failed and true_content_length and false_content_length were not set ")
        # If we got both then get their lengths 
        true_content_length = len(true_response.content)
        false_content_length = len(false_response.content)
        # If the true length is greater than twice the false length return True
        if true_content_length > 2*false_content_length:
            if self.hadoop_reporting:
                logger.info("Found a Blind SQL result with true response content of %s and false of %s", true_content_length, false_content_length)
            return True
        else:   # Else return False
            if self.hadoop_reporting:
                logger.info("No Blind SQL with true response content of %s and false of %s", true_content_length, false_content_length)
            return False

    def fuzz(self):
        """ Make all our targets fuzzy and deploy their payloads. 
        
        returns     list of Result objects.
        """
        self.__build_fuzzy_target_groups()
        results = []
        for ftg in self.fuzzy_target_groups:
            result_dic = {}
            try:
                if ftg.fuzzy_targets[0].unfuzzed_target in self.unstable_targets:
                    logger.info("Target %s is unstable so marking bsqli result as false", ftg.fuzzy_targets[0].unfuzzed_target)
                    result_dic["bsqli"] = False
                else:
                    # BSQLI check
                    result_dic["bsqli"] = self.check_for_bsqli(ftg)
            except:
                if self.hadoop_reporting:
                    logger.info("Caught exception trying to perform BSQLi check on %s :", ftg.fuzzy_targets[0].unfuzzed_target, exec_info=True)
                    result_dic["bsqli"] = False
            results.append(Result(ftg.fuzzy_targets[0], result_dic))
        return results
