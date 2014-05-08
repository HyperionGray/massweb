import time
import json
import requests
import sys
from urlparse import parse_qs
from urlparse import urlparse
from urlparse import urlunparse
from urllib import urlencode
from multiprocessing import Process, Pool, Queue, current_process
from multiprocessing.pool import ThreadPool
from multiprocessing import TimeoutError
import traceback
from sets import Set
from massweb.pnk_net.pnk_request import pnk_request_raw
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.payloads.payload import Payload

class MassRequest(object):

    def __init__(self, num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}]):

        self.num_threads = num_threads
        self.time_per_url = time_per_url
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list

        self.results = []
        self.urls_finished = []
        self.urls_attempted = []

        self.targets_results = []
        self.targets_finished = []
        self.targets_attempted = []

    def add_to_finished(self, x):

        self.urls_finished.append(x[0])
        self.results.append(x)

    def add_to_finished_targets(self, x):

        self.targets_finished.append(x[0])
        self.targets_results.append(x)

    def get_urls(self, urls):

        timeout = float(self.time_per_url * len(urls))
        pool = Pool(processes = self.num_threads)
        proc_results = []

        for url in urls:
            self.urls_attempted.append(url)
            proc_result = pool.apply_async(func = pnk_request_raw, args = (url, self.request_timeout, self.proxy_list), callback = self.add_to_finished)
            proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()
        list_diff = Set(self.urls_attempted).difference(Set(self.urls_finished))

        for url in list_diff:
            sys.stderr.write("URL %s got timeout" % url)
            self.results.append((url, "__PNK_GET_THREAD_TIMEOUT"))

    def get_fuzzy_targets(self, targets):

        timeout = float(self.time_per_url * len(targets))
        pool = Pool(processes = self.num_threads)
        proc_results = []

        for target in targets:
            self.targets_attempted.append(target)
            proc_result = pool.apply_async(func = pnk_request_raw, args = (target, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
            proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                sys.stderr.write("Handled exception:")
                traceback.print_exc()
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

        list_diff = Set(self.targets_attempted).difference(Set(self.targets_finished))

        for target in list_diff:
            sys.stderr.write("URL %s got timeout" % str(target))
            self.targets_results.append((target, "__PNK_GET_THREAD_TIMEOUT"))

    def post_urls(self, urls_and_data):

        #totally untested
        timeout = float(self.time_per_url * len(urls))
        pool = Pool(processes = self.num_threads)
        proc_results = []

        for url_and_datum in url_and_data:
            url = url_and_datum[0]
            datum = url_and_datum[1]

            self.urls_attempted.append(url)
            proc_result = pool.apply_async(func = pnk_post_raw, args = (url, datum), callback = self.add_to_finished)
            proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                traceback.print_exc()
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()
        list_diff = Set(self.urls_attempted).difference(Set(self.urls_finished))

        for url in list_diff:
            self.results.append((url, "__PNK_POST_THREAD_TIMEOUT"))

if __name__ == "__main__":

#    urls_to_fuzz = ["http://www.pastease.com.au/cart.add?product=33&code=2601BL&price=24.95", "http://www.google.com/", 
#                    "http://www.hyperiongray.com", "http://www.sfgcd.com/ProductsBuy.asp?ProNo=2013-5-3&ProName=%22%3E%3CSCrIpT%3Ealert%287106%29%3C%2FScRiPt%3E"]

#    targ1 = FuzzyTarget(url = "http://www.pastease.com.au/cart.add?product=33&code=2601BL&price=24.95", payload = Payload("ddd", ["xss"]))
#    targ2 = FuzzyTarget(url = "http://www.hyperiongray.com", payload = Payload("fff", ["sqli"]))
#    targ3 = FuzzyTarget(url = "http://www.sfgcd.com/ProductsBuy.asp?ProNo=2013-5-3&ProName=%22%3E%3CSCrIpT%3Ealert%287106%29%3C%2FScRiPt%3E", payload = Payload("fff", ["sqli"]))
#    targ4 = FuzzyTarget(url = "http://www.google.com/", payload = Payload("fff", ["sqli"]))

#    targets_to_fuzz = [targ1, targ2, targ3, targ4]
    f = open("out_urls_to_fuzz_1mil")
    targets_to_fuzz = []
    for line in f:
        url = line.strip()
        targets_to_fuzz.append(url)

    mr = MassRequest()
    mr.get_fuzzy_targets(targets_to_fuzz)

    for r in mr.targets_results:
        target = r[0]
        print target, r[1][0:100]
        print "============================================================================"
#        print target.payload
#        print target.payload.check_type_list
#        print target.payload.payload_str
#        print r[1][0:10]


#    mr.get_urls(urls_to_fuzz)
#    print "attemped"
#    print mr.urls_attempted 
#
#    print "finished"
#    print mr.urls_finished 
#
#    print "results:"
#    for r in mr.results:
#        print r[0], r[1][0:10]
#
#    for x in get_urls(urls_to_fuzz):
#        print x[0], x[1][0:10]
