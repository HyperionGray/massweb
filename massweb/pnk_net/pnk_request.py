import sys
import time
import json
import requests
import traceback
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.proxy_rotator.proxy_rotate import get_random_proxy

def pnk_request_raw(url_or_target, req_timeout = 5, proxy_list = [{}]):
    
    if proxy_list[0]:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}

    try:
        if isinstance(url_or_target, str):

            sys.stderr.write("Requesting: %s with proxy %s\n" % (str(url_or_target), str(proxy)))
            r = requests.get(url_or_target, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

        if isinstance(url_or_target, FuzzyTarget):

            sys.stderr.write("Requesting: %s with proxy %s\n" % (str(url_or_target), str(proxy)))
            r = requests.get(url_or_target.url, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r.text)

    except:
        #threads suck at exceptions, use this to mark failure
        traceback.print_exc()
        sys.stderr.write("A request failed to URL %s\n" % url_or_target)
        return (url_or_target, "__PNK_REQ_FAILED")

def pnk_post_raw(url, datum):

    sys.stderr.write("Requesting: %s\n" % url)

    try:
        r = requests.post(url, data = datum, proxies = {}, timeout = timeout)
        return (url, r.text)

    except:
        #threads suck at exceptions, use this to mark failure
        return (url, "__PNK_POST_FAILED")

