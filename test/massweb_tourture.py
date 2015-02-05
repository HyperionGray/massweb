#!/usr/bin/env python2

import logging as logger
import os
import sys
import unittest

from massweb.masscrawler.masscrawl import MassCrawl
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.fuzzers.bsqli_fuzzer import BSQLiFuzzer
from massweb.payloads.bsqli_payload import BSQLIPayload
from massweb.payloads.bsqli_payload_group import BSQLIPayloadGroup
from massweb.payloads.payload import Payload

logger.basicConfig(level=logger.DEBUG)

LOGFILE = "massweb_torture.log"
MASTER_LOGFILE = "massweb_torture.master.log"

# User and password for proxy are taken from environmental variables
user = os.environ.get("PROXY_USER")
passwd = os.environ.get("PROXY_PASS")
proxies = {"http": "http://%s:%s@proxy.crawlera.com:8010" % (user, passwd)}
proxy_scan_list = [proxies]

def fuzz(targets):
    xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])
    sqli_xpathi_payload = Payload("')--#", check_type_list = ["sqli", "xpathi"])
    trav_payload = Payload('../../../../../../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list = ["trav"])
    xpathi_payload = Payload('<!--', check_type_list = ["xpathi"])
    osci_payload = Payload('; cat /etc/passwd')
    wf = WebFuzzer(targets, num_threads=25, time_per_url=5, request_timeout=4, proxy_list=proxy_scan_list, hadoop_reporting=True)
    wf.add_payload(xss_payload)
    wf.add_payload(sqli_xpathi_payload)
    wf.add_payload(trav_payload)
    wf.add_payload(xpathi_payload)
    wf.add_payload(osci_payload)
    wf.generate_fuzzy_targets()
    wf_results = wf.fuzz()
    generic_true_payload =  BSQLIPayload(" AND 1=1", {"truth": True})
    generic_false_payload =  BSQLIPayload(" AND 1=2", {"truth": False})
    generic_payload_group = BSQLIPayloadGroup(generic_true_payload, generic_false_payload)
    dump_true_payload = BSQLIPayload(" OR 1=1", {"truth": True})
    dump_false_payload = BSQLIPayload(" OR 1=2", {"truth": False})
    dump_payload_group = BSQLIPayloadGroup(dump_true_payload, dump_false_payload)
    payload_groups = [generic_payload_group, dump_payload_group]
    bf = BSQLiFuzzer(targets, bsqli_payload_groups=payload_groups, hadoop_reporting=True, num_threads=10)
    bf_results = bf.fuzz()
    for result in wf_results:
        yield result
    for result in bf_results:
        yield result

def mapper(output_file):
    seeds = get_stdin()
    mc = MassCrawl(seeds)
    logger.info("Adding seeds:")
    for seed in seeds:
        logger.info(mc.get_domain_from_url(seed))
        mc.add_to_scope_from_url(seed)
    mc.crawl(depth=3, num_threads=25, time_per_url=5, request_timeout=4, proxy_list=proxy_scan_list)
    if mc.targets:
        results = fuzz(mc.targets)
        for result in results:
            domain = mc.get_domain_from_url(result.fuzzy_target.url)
            output_file.write("domain: %s \\\\ results: %s\n" % (domain, result))
    else:
        logger.error("URL had no mc.targets for some reason... dump of seeds: %s", seeds)
        output_file.write("domain: %s \\\\ ERROR: no targets\n" % domain)

def get_stdin():
    seeds = []
    for line in sys.stdin:
        url = line.strip("\n")
        seeds.append(url)
    return seeds

def just_run():
    """ run the tests and dump output to a file. """
    output_file = open("massweb_torture.log", "wb")
    mapper(output_file)
    output_file.close() 

def get_sorted_file(filename):
    """ get output from file and sort it """
    fh = open(filename, "rb")
    slist = sort_file(fh)
    return "\n".join(slist)

def sort_file(fh):
    """ sort the contents of a file handle. """
    lst = list(fh.readlines())
    lst.sort()
    return lst

# Pretend unittest :D
class TestMassweb(unittest.TestCase):
    
    def test_massweb(self):
        just_run()
        branch = get_sorted_file(LOGFILE)
        master = get_sorted_file(MASTER_LOGFILE)
        # warm fuzzies for the humans
        print(len(branch), len(master))
        print(branch==master)
        # this will probably fail
        self.assertEqual(branch, master)


if __name__ == "__main__":
    # if there is no output from this test run from the master branch or whatever the baseline is then make it and tell the human to put it where it belongs.
    if not os.path.exists(MASTER_LOGFILE):
        just_run()
        logger.error("Created new output log. Move to %s and then run again.", MASTER_LOGFILE)
    else:
        # otherwise pretend that this is a unittest.
        unittest.main()
