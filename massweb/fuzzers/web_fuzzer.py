""" Web Fuzzer Class. """

import codecs
import logging
import sys
from urlparse import parse_qs, urlparse

from massweb.fuzzers.ifuzzer import iFuzzer

from massweb.mass_requests.mass_request import MassRequest
from massweb.mass_requests.response_analysis import parse_worthy

from massweb.results.result import Result

from massweb.targets.fuzzy_target import FuzzyTarget

from massweb.vuln_checks.mxi import MXICheck
from massweb.vuln_checks.osci import OSCICheck
from massweb.vuln_checks.sqli import SQLICheck
from massweb.vuln_checks.trav import TravCheck
from massweb.vuln_checks.xpathi import XPathICheck
from massweb.vuln_checks.xss import XSSCheck

# setup logger object
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('WebFuzzer')
logger.setLevel(logging.INFO)

# force stdin and stderr to use utf-8
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

class WebFuzzer(iFuzzer):
    """ Fuzzy a generated list of Targets.

    Generates lists of targets with associated payloads and runs them against
    the target systems.
    """

    def __init__(self, targets=None, payloads=None, num_threads=10,
                 time_per_url=10, request_timeout=10, proxy_list=None,
                 hadoop_reporting=False, depreciated=None):
        """ Initialize this WebFuzzer object.

        targets             list of Target objects. Default [].
        payloads            list of Payload objects. Default [].
        num_threads         Number of threads/processes to launch as an int.
                                Default 10.
        time_per_url        Time in seconds to spend on each Target.
                                Default 10.
        request_timeout     Time in seconds to wait for a connection before
                                giving up. Default 10.
        proxy_list          list of proxies specified as dicts. Default empty.
        hadoop_reporting    Output info for hadoop if True. Default False.
        payload_groups      UNUSED. list of groups of Payload objects.
                                Default [].
        """
        super(WebFuzzer, self).__init__()
        # do this because we may need to create more MassRequest objects in
        #  checks (like bsqli), needs to be configured the same
        self.mreq_config_dict = {"num_threads": num_threads,
                                 "time_per_url": time_per_url,
                                 "request_timeout": request_timeout,
                                 "proxy_list": proxy_list or [{}],
                                 "hadoop_reporting": hadoop_reporting}
        self.mreq = MassRequest(**self.mreq_config_dict)
        self.targets = targets or []
        self.payloads = payloads or []
        self.mxi_check = MXICheck()
        self.osci_check = OSCICheck()
        self.sqli_check = SQLICheck()
        self.trav_check = TravCheck()
        self.xpathi_check = XPathICheck()
        self.xss_check = XSSCheck()
        self.hadoop_reporting = hadoop_reporting
        if self.hadoop_reporting:
            logger.info("Hadoop reporting set in fuzzer")
        self.fuzzy_targets = []

    def __generate_fuzzy_target_get(self, target):
        """ Associate fuzzing data for GET requests with the target.

        target  Target object.
        returns list of Targets with fuzzing data.
        """
        url = target.url
        parsed_url = urlparse(url)
        parsed_url_query = parsed_url.query
        url_q_dic = parse_qs(parsed_url_query)
        fuzzy_targets = []
        for query_param, _ in url_q_dic.iteritems():
            for payload in self.payloads:
                fuzzy_url = (self.replace_param_value(url, query_param,
                                                      str(payload)))
                fuzzy_target = FuzzyTarget(fuzzy_url, url, query_param, "get",
                                           payload=payload)
                fuzzy_targets.append(fuzzy_target)
        return fuzzy_targets

    def __generate_fuzzy_target_post(self, target):
        """ Associate fuzzing data for POST requests with the target.

        target  Target object.
        returns list of Targets with fuzzing data.
        """
        url = target.url
        fuzzy_targets = []
        post_keys = target.data.keys()
        for key in post_keys:
            data_copy = target.data.copy()
            for payload in self.payloads:
                data_copy[key] = str(payload)
                fuzzy_target = FuzzyTarget(url, url, key, "post",
                                           data=data_copy.copy(),
                                           payload=payload,
                                           unfuzzed_data=target.data)
                fuzzy_targets.append(fuzzy_target)
        return fuzzy_targets

    def generate_fuzzy_targets(self):
        """ Associate fuzzing data with the targets. """
        if self.hadoop_reporting:
            logger.info("Generating fuzzy targets")
        # If no targets then raise an exception
        if len(self.targets) == 0:
            raise ValueError("Targets list must not be empty!")
        self.fuzzy_targets = []
        for target in self.targets:
            if target.ttype == "get":
                fuzzy_target_list = self.__generate_fuzzy_target_get(target)
                self.fuzzy_targets += fuzzy_target_list
            if target.ttype == "post":
                fuzzy_target_list = self.__generate_fuzzy_target_post(target)
                self.fuzzy_targets += fuzzy_target_list
        if not self.fuzzy_targets:
            raise ValueError("fuzzy_targets is empty. No targets generated"
                             " from: %s",
                             ','.join([str(x) for x in self.targets]))
        return self.fuzzy_targets

    def fuzz(self):
        """ Fuzz all the targets and return the results.

        returns     list of Result objects.
        """
        self.mreq.request_targets(self.fuzzy_targets)
        results = []
        for target, response in self.mreq.results:
            #FIXME: Clarify with alex: !not yet multithreaded, should it be?
            try:
                result = self.analyze_response(target, response)
            except (TypeError, AttributeError):
                # If request failed and str is returned instead of Response obj
                #  could save some cycles here not analyzing response
                if self.hadoop_reporting:
                    logger.info("Marking target as failed due to exception: ", exc_info=True)
                result = self.analyze_response(ftarget, "__PNK_FAILED_RESPONSE")
            results.append(result)
        return results

    def _make_failed_result(self, target):
        """ Macro to make a failed Result. """
        result_dic = {}
        for check_type in target.payload.check_type_list:
            result_dic[check_type] = False
        return Result(target, result_dic)

    def analyze_response(self, ftarget, response):
        """ Analyze the results of the request and return the info gathered.

        ftargeet    Target object.
        response    requests.Respnse object.

        returns     Result object.
        raises      TypeError or AttributeError when non requests.Response is given as response.

        """
        #FIXME: Clarify with alex: !function is a mess, response is of type
        #    text or non-text, trying to read blah blah
        result_dic = {}
        check_type_list = ftarget.payload.check_type_list
        if self.hadoop_reporting:
            logger.info(u"Response is of type %s for target %s",
                        response.__class__.__name__, ftarget)
        worthy = parse_worthy(response,
                              hadoop_reporting=self.hadoop_reporting)
        if worthy:
            logger.info("Target %s looks worth checking for vulnerabilities.",
                        ftarget)
        else:
            logger.info("Response deemed non-parse-worthy. Setting all checks "
                        "in result_dic to False for %s", ftarget)
            return self._make_failed_result(ftarget)
        result_dic = self._run_checks(response, result_dic, check_type_list)
        return Result(ftarget, result_dic)

    def _run_checks(self, response, result_dic, check_type_list):
        """ Check reponse output with the specified checkers.

        response        requests.Response object.
        result_dic      dict with checker names as keys.
        check_type_list list of names of checkers to check with.
        """
        #FIXME: Make me work on a dict of checker IDs and methods to call
        #   instead of an if statement cascade
        if "mxi" in check_type_list:
            mxi_result = self.mxi_check.check(response.text)
            result_dic["mxi"] = mxi_result
        if "sqli" in check_type_list:
            sqli_result = self.sqli_check.check(response.text)
            result_dic["sqli"] = sqli_result
        if "xpathi" in check_type_list:
            xpathi_result = self.xpathi_check.check(response.text)
            result_dic["xpathi"] = xpathi_result
        if "trav" in check_type_list:
            trav_result = self.trav_check.check(response.text)
            result_dic["trav"] = trav_result
        if "osci" in check_type_list:
            osci_result = self.osci_check.check(response.text)
            result_dic["osci"] = osci_result
        if "xss" in check_type_list:
            xss_result = self.xss_check.check(response.text)
            result_dic["xss"] = xss_result
        return result_dic
