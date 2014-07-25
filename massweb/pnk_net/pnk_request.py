import sys
import time
import json
import requests
import traceback
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.target import Target
from massweb.proxy_rotator.proxy_rotate import get_random_proxy

def pnk_request_raw(url_or_target, request_type = "get", data = None, req_timeout = 5, proxy_list = [{}]):

    if proxy_list[0]:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}

    try:
        if isinstance(url_or_target, str) and request_type == "get":

            sys.stderr.write("Requesting: %s with proxy %s\n" % (str(url_or_target), str(proxy)))
            r = requests.get(url_or_target, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

        if isinstance(url_or_target, str) and request_type == "post":

            sys.stderr.write("Requesting: %s with proxy %s and data %s\n" % (str(url_or_target), str(proxy), str(data)))
            r = requests.post(url_or_target, data = data, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

        if (isinstance(url_or_target, FuzzyTarget) or isinstance(url_or_target, Target)) and request_type == "get":

            print "pnk_net", request_type
            sys.stderr.write("Requesting: %s with proxy %s\n" % (str(url_or_target), str(proxy)))
            r = requests.get(url_or_target.url, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

        if (isinstance(url_or_target, FuzzyTarget) or isinstance(url_or_target, Target)) and request_type == "post":

            sys.stderr.write("Requesting: %s with proxy %s and data %s\n" % (str(url_or_target), str(proxy), str(data)))
            r = requests.post(url_or_target.url, data = data, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

    except:
        #threads suck at exceptions, use this to mark failure
        sys.stderr.write("Handled Exception:")
        traceback.print_exc()
        #sys.stderr.write("A request failed to URL %s\n" % url_or_target)
        return (url_or_target, "__PNK_REQ_FAILED")

def pnk_post_raw_dep(url, datum = None, req_timeout = 5, proxy_list = [{}]):

    #model
    sys.stderr.write("Requesting: %s\n" % url)

    if proxy_list[0]:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}

    try:
        r = requests.post(url, data = datum, proxies = proxy, timeout = req_timeout)
        return (url, r.text)

    except:
        #threads suck at exceptions, use this to mark failure
        traceback.print_exc()
        return (url, "__PNK_POST_FAILED")

