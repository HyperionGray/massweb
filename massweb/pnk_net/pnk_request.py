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

        if (isinstance(url_or_target, unicode) or isinstance(url_or_target, str)) and request_type == "get":

            url_or_target = url_or_target.strip()
            r = requests.get(url_or_target, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r)

        if (isinstance(url_or_target, unicode) or isinstance(url_or_target, str)) and request_type == "post":

            url_or_target = url_or_target.strip()
            r = requests.post(url_or_target, data = data, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r)

        if (isinstance(url_or_target, Target)) and request_type == "get":

            r = requests.get(url_or_target.url, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r)

        if (isinstance(url_or_target, Target)) and request_type == "post":

            r = requests.post(url_or_target.url, data = data, proxies = proxy, timeout = req_timeout)
            return (url_or_target, r)

    except:
        #threads suck at exceptions (or I do?), use this to mark failure
        return (url_or_target, "__PNK_REQ_FAILED")
