""" """

import os
import unittest

from massweb.targets.target import Target
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.fuzzers.bsqli_fuzzer import BSQLiFuzzer
from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.bsqli_payload_group import BSQLIPayloadGroup
from massweb.payloads.payload import Payload

RUN_INTEGRATION_TESTS = os.environ.get("MASSWEB_RUN_INTEGRATION_TESTS") == "1"
INTEGRATION_TARGETS = [
    u.strip()
    for u in os.environ.get("MASSWEB_INTEGRATION_TARGETS", "").split(",")
    if u.strip()
]
HTTP_PROXY = os.environ.get("MASSWEB_HTTP_PROXY")
proxy_scan_list = [{"http": HTTP_PROXY, "https": HTTP_PROXY}] if HTTP_PROXY else [{}]

targets = [Target(x) for x in INTEGRATION_TARGETS]

payloads = [Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"]),
    Payload('../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list = ["trav"]),
    Payload("')--", check_type_list = ["sqli", "xpathi"])]

@unittest.skipUnless(
    RUN_INTEGRATION_TESTS and INTEGRATION_TARGETS,
    "Network integration tests are disabled by default. "
    "Set MASSWEB_RUN_INTEGRATION_TESTS=1 and MASSWEB_INTEGRATION_TARGETS=url1,url2",
)
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
        self.assertIsInstance(result, list)


    def test_webfuzzer(self):
        wf = WebFuzzer(targets, num_threads=25, time_per_url=5, request_timeout=4, proxy_list=proxy_scan_list, hadoop_reporting=False)
        for payload in payloads:
            wf.add_payload(payload)
        wf.generate_fuzzy_targets()
        result = wf.fuzz()
        self.assertIsInstance(result, list)
        

if __name__ == '__main__':
    unittest.main()
