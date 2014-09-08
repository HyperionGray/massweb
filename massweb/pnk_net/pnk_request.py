import sys
import time
import json
import requests
import traceback
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.target import Target
from massweb.proxy_rotator.proxy_rotate import get_random_proxy
import codecs
import logging
from logging import StreamHandler
logging.basicConfig(format='%(asctime)s %(name)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('pnknet')
logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

def pnk_request_raw(url_or_target, request_type = "get", data = None, req_timeout = 5, proxy_list = [{}], hadoop_reporting = False):

    if proxy_list[0]:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}

    try:

        if (isinstance(url_or_target, unicode) or isinstance(url_or_target, str)) and request_type == "get":

            if hadoop_reporting:
                logger.info(u"GET requesting %s" % unicode(url_or_target))

            url_or_target = url_or_target.strip()
            r = requests.get(url_or_target, proxies = proxy, timeout = req_timeout, allow_redirects = False)
            return (url_or_target, r)

        if (isinstance(url_or_target, unicode) or isinstance(url_or_target, str)) and request_type == "post":

            if hadoop_reporting:
                logger.info(u"POST requesting %s" % unicode(url_or_target))

            url_or_target = url_or_target.strip()
            r = requests.post(url_or_target, data = data, proxies = proxy, timeout = req_timeout, allow_redirects = False)
            return (url_or_target, r)

        if (isinstance(url_or_target, Target)) and request_type == "get":

            if hadoop_reporting:
                logger.info(u"GET requesting %s" % unicode(url_or_target))

            r = requests.get(url_or_target.url, proxies = proxy, timeout = req_timeout, allow_redirects = False)
            return (url_or_target, r)

        if (isinstance(url_or_target, Target)) and request_type == "post":

            if hadoop_reporting:
                logger.info(u"POST requesting %s" % unicode(url_or_target))

            r = requests.post(url_or_target.url, data = data, proxies = proxy, timeout = req_timeout, allow_redirects = False)
            return (url_or_target, r)

    except:
        #threads suck at exceptions (or I do?), use this to mark failure
        return (url_or_target, "__PNK_REQ_FAILED")
