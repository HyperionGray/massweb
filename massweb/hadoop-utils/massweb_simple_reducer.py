#!/usr/bin/python2.7

import json
import sys
import urlparse
import traceback

for line in sys.stdin:

    line = line.strip()
    domain_in, result_dic_in = line.split("\t")
    print domain_in + "\t" + result_dic_in
