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
import codecs
import logging
from logging import StreamHandler
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('MassRequest')
logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

class MassRequest(object):

    def __init__(self, num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}], hadoop_reporting = False):

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
        
        self.hadoop_reporting = hadoop_reporting
        if self.hadoop_reporting:
            logger.info(u"Instantiated MassRequest object with %s threads and %s time per url" % (unicode(num_threads), unicode(time_per_url)))

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

            if self.hadoop_reporting:
                proc_result = pool.apply_async(func = pnk_request_raw, args = (url, "get", None, self.request_timeout, self.proxy_list, True), callback = self.add_to_finished)
            else:                
                proc_result = pool.apply_async(func = pnk_request_raw, args = (url, "get", None, self.request_timeout, self.proxy_list), callback = self.add_to_finished)
            proc_results.append(proc_result)

        if self.hadoop_reporting:
            logger.info(u"Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info(u"Thread timed out or threw exception, killing it and replacing it")

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

        if self.hadoop_reporting:
            logger.info("Getting %s targets" % unicode(len(targets)))

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
                if self.hadoop_reporting:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list, True), callback = self.add_to_finished_targets)
                else:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)


        if self.hadoop_reporting:
            logger.info("Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info(u"Thread timed out or threw exception, killing it and replacing it")

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

        if self.hadoop_reporting:
            logger.info(u"Posting %s targets" % unicode(len(targets)))

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
                if self.hadoop_reporting:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list, True), callback = self.add_to_finished_targets)
                else:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)


        if self.hadoop_reporting:
            logger.info(u"Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info("Thraed timed out or threw exception, killing it and replacing it")

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
            if self.hadoop_reporting:
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list, True), callback = self.add_to_finished_targets)
            else:
                proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
            proc_results.append(proc_result)


        if self.hadoop_reporting:
            logger.info(u"Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info("Thraed timed out or threw exception, killing it and replacing it")

                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()
        list_diff = Set(self.urls_attempted).difference(Set(self.urls_finished))

        for url in list_diff:
            self.results.append((url, "__PNK_THREAD_TIMEOUT"))

    def get_post_requests_from_targets(self, targets):

        if self.hadoop_reporting:
            logger.info(u"Identifying post requests from %s targets" % unicode(len(targets)))

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
                if self.hadoop_reporting:
                    proc_result = pool.apply_async(func = find_post_requests, args = (url, None, True, True), callback = self.add_to_identified_post)
                    
                else:
                    proc_result = pool.apply_async(func = find_post_requests, args = (url, None, True), callback = self.add_to_identified_post)

                proc_results.append(proc_result)
        
        if self.hadoop_reporting:
            logger.info(u"Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info(u"Thread timed out or threw exception, killing it and replacing it")

                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

    def request_targets(self, targets):

        if self.hadoop_reporting:
            logger.info(u"Requesting %s targets" % unicode(len(targets)))

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
                if self.hadoop_reporting:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list, True), callback = self.add_to_finished_targets)

                else:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "post", target.data, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)

                proc_results.append(proc_result)

            if target.ttype == "get":
                self.targets_attempted.append(target)

                if self.hadoop_reporting:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list, True), callback = self.add_to_finished_targets)

                else:
                    proc_result = pool.apply_async(func = pnk_request_raw, args = (target, "get", None, self.request_timeout,  self.proxy_list), callback = self.add_to_finished_targets)
                proc_results.append(proc_result)

        if self.hadoop_reporting:
            logger.info(u"Giving each URL %s seconds to respond" % unicode(self.time_per_url))

        for pr in proc_results:

            try:
                pr.get(timeout = self.time_per_url)

            except:

                if self.hadoop_reporting:
                    traceback.print_exc()
                    logger.info(u"Thread timed out or threw exception, killing it and replacing it")

                pool.terminate()
                pool.join()

        pool.terminate()
        pool.join()

        list_diff = Set(self.targets_attempted).difference(Set(self.targets_finished))
        del self.targets_attempted
        del self.targets_finished

        if self.hadoop_reporting:
            logger.info(u"Determining timed out targets")

        for target in list_diff:
            #sys.stderr.write("URL %s got timeout" % str(target))
            self.targets_results.append((target, "__PNK_THREAD_TIMEOUT"))

        if self.hadoop_reporting:
            logger.info(u"Finished determining timed out targets")

if __name__ == "__main__":

    targ1 = FuzzyTarget(u"http://course.hyperiongray.com/vuln1/formhandler.php", "password", data = {"password" : "%27"}, ttype = "post", payload = Payload("%27", ["sqli"]))
    targ2 = FuzzyTarget(u"http://www.hyperiongray.com/?dd=eee", "dd", payload = Payload("fff", ["sqli"]))

    targets = [targ1, targ2]
    mr = MassRequest(hadoop_reporting = True)
    mr.get_post_requests_from_targets(targets)
    mr.request_targets(targets)
#

    for r in mr.results:
        target = r[0]
        print target, r[1][0:100]
        print "============================================================================"
        print target.payload
        print target.payload.check_type_list
        print target.payload.payload_str
        print r[1][0:10]


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
