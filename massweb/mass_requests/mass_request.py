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
import os 
from bs4 import BeautifulSoup, SoupStrainer
from urlparse import urlparse, urlunparse
from requests.exceptions import ConnectionError
import urllib
from massweb.pnk_net.pnk_request import pnk_request_raw
from massweb.pnk_net.find_post import find_post_requests
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

class MassRequest(object):

    def __init__(self, num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}]):

        self.num_threads = num_threads
        self.time_per_url = time_per_url
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list

        self.results = []
        #!
        self.targets_results = []
        self.urls_finished = []
        self.urls_attempted = []

        self.targets_finished = []
        self.targets_attempted = []
        self.identified_post_requests = []

    def add_to_identified_post(self, x):

        for post_request in x:
            self.identified_post_requests.append(post_request)

    def add_to_finished(self, x):

        self.urls_finished.append(x[0])
        self.results.append(x)

    def add_to_finished_targets(self, x):

        self.targets_finished.append(x[0])
        self.results.append(x)

    def get_urls(self, urls):

        try:
            timeout = float(self.time_per_url * len(urls))
        except:
            url_num = 0
            for url in urls:
                url_num += 1

            timeout = float(self.time_per_url * url_num)
            urls.seek(0)

        pool = Pool(processes = self.num_threads)
        proc_results = []

        for url in urls:
            self.urls_attempted.append(url)
            proc_result = pool.apply_async(func = pnk_request_raw, args = (url, "get", None, self.request_timeout, self.proxy_list), callback = self.add_to_finished)
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
        del self.urls_attempted
        del self.urls_finished

        for url in list_diff:
            #sys.stderr.write("URL %s got timeout" % url)
            self.results.append((url, "__PNK_THREAD_TIMEOUT"))

    def get_targets(self, targets):

        try:
            timeout = float(self.time_per_url * len(targets))
        except:
            url_num = 0
            for url in targets:
                url_num += 1
            targets.seek(0)


        pool = Pool(processes = self.num_threads)
        proc_results = []

        for target in targets:
            if target.ttype == "get":
                self.targets_attempted.append(target)
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

        list_diff = Set(self.targets_attempted).difference(Set(self.targets_finished))
        del self.targets_attempted
        del self.targets_finished

        for target in list_diff:
            #sys.stderr.write("URL %s got timeout" % str(target))
            self.targets_results.append((target, "__PNK_THREAD_TIMEOUT"))

    def post_targets(self, targets):

        try:
            timeout = float(self.time_per_url * len(targets))
        except:
            url_num = 0
            for url in targets:
                url_num += 1
            targets.seek(0)

        pool = Pool(processes = self.num_threads)
        proc_results = []

        for target in targets:
            if target.ttype == "post":
                self.targets_attempted.append(target)
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

        list_diff = Set(self.targets_attempted).difference(Set(self.targets_finished))
        del self.targets_attempted
        del self.targets_finished

        for target in list_diff:
            #sys.stderr.write("URL %s got timeout" % str(target))
            self.targets_results.append((target, "__PNK_THREAD_TIMEOUT"))

    def post_urls(self, urls_and_data):

        try:
            timeout = float(self.time_per_url * len(urls_and_data))
        except:
            url_num = 0
            for url in urls_and_data:
                url_num += 1

            urls_and_data.seek(0)

        pool = Pool(processes = self.num_threads)
        proc_results = []

        for url_and_datum in urls_and_data:
            url = url_and_datum[0]
            datum = url_and_datum[1]

            self.urls_attempted.append(url)
            proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
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
            self.results.append((url, "__PNK_THREAD_TIMEOUT"))

    def get_post_requests_from_targets(self, targets):

        try:
            timeout = float(self.time_per_url * len(targets))
        except:
            url_num = 0
            for url in targets:
                url_num += 1

            targets.seek(0)

        pool = Pool(processes = self.num_threads)
        proc_results = []

        for target in targets:
            url = target.url
            
            if target.ttype == "get":
                self.targets_attempted.append(target)
                proc_result = pool.apply_async(func = find_post_requests, args = (url, None, True), callback = self.add_to_identified_post)
                proc_results.append(proc_result)
        
        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

    def request_targets(self, targets):

        try:
            timeout = float(self.time_per_url * len(targets))
        except:
            url_num = 0
            for url in targets:
                url_num += 1

            targets.seek(0)

        pool = Pool(processes = self.num_threads)
        proc_results = []

        for target in targets:
            if target.ttype == "post":
                self.targets_attempted.append(target)
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)

            if target.ttype == "get":
                self.targets_attempted.append(target)
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)

        for pr in proc_results:

            try:
                pr.get(timeout = timeout)

            except:
                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

        list_diff = Set(self.targets_attempted).difference(Set(self.targets_finished))
        del self.targets_attempted
        del self.targets_finished

        for target in list_diff:
            #sys.stderr.write("URL %s got timeout" % str(target))
            self.targets_results.append((target, "__PNK_THREAD_TIMEOUT"))

if __name__ == "__main__":

    f = open("urlssmall.txt")
    mr = MassRequest(num_threads = 20, time_per_url = 2)
    
    mr.get_urls(f.readlines())
    print mr.results

#    urls_to_fuzz = ["http://www.pastease.com.au/cart.add?product=33&code=2601BL&price=24.95", "http://www.google.com/", 
#                    "http://www.hyperiongray.com", "http://www.sfgcd.com/ProductsBuy.asp?ProNo=2013-5-3&ProName=%22%3E%3CSCrIpT%3Ealert%287106%29%3C%2FScRiPt%3E"]

#    targ1 = Target(url = "http://www.pastease.com.au/cart.add?product=33&code=2601BL&price=24.95")
#    targ2 = Target(url = "http://www.hyperiongray.com", payload = Payload("fff", ["sqli"]))
#    targ3 = FuzzyTarget(url = "http://www.sfgcd.com/ProductsBuy.asp?ProNo=2013-5-3&ProName=%22%3E%3CSCrIpT%3Ealert%287106%29%3C%2FScRiPt%3E", payload = Payload("fff", ["sqli"]))
#    targ4 = FuzzyTarget(url = "http://www.google.com/", payload = Payload("fff", ["sqli"]))

#    targ1 = Target(url = "http://course.hyperiongray.com/vuln1")

#    targets = [targ1]
#    mr = MassRequest()
#    mr.get_post_requests_from_targets(targets)

#    for t in mr.identified_post_requests:
#        print t

#    targets_to_fuzz = [targ3, targ4]
#    f = open("out_urls_to_fuzz_1mil")
#    targets_to_fuzz = []
#    for line in f:
#        url = line.strip()
#        targets_to_fuzz.append(url)\

#    targ1 = FuzzyTarget(url = "http://course.hyperiongray.com/vuln1eeeeeeeee/formhandler.php", data = {"password" : "%27"}, ttype = "post", payload = Payload("%27", ["sqli"]))
#    targ2 = FuzzyTarget(url = "http://www.hyperiongray.com", payload = Payload("fff", ["sqli"]))

#    targets = [targ1, targ2]
#    mr = MassRequest()
#    mr.request_targets(targets)
#    print mr.results
#
#
#    for r in mr.results:
#        target = r[0]
#        print target, r[1][0:100]
#        print "============================================================================"
#        print target.payload
#        print target.payload.check_type_list
#        print target.payload.payload_str
#        print r[1][0:10]


#    mr.get_urls(urls_to_fuzz)
#    print mr.results
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
