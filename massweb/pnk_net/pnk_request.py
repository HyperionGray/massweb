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
logger.setLevel(logging.DEBUG)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

def pnk_request_raw(target, request_type="get", data=None, req_timeout=5, proxy_list=[{}], hadoop_reporting=False, **kwargs):

    if proxy_list[0]:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}

    try:
        if request_type == "post":
            logger.debug(" POST Data: %s", target.data)
        if isinstance(target, basestring) and request_type == "get":

            if hadoop_reporting:
                logger.info("GET requesting %s", target)

            target = target.strip()
            response = requests.get(target, proxies=proxy, timeout=req_timeout, allow_redirects=False, **kwargs)
            return (target, response)

        if isinstance(target, basestring) and request_type == "post":

            if hadoop_reporting:
                logger.info("POST requesting %s", target)

            target = target.strip()
            response = requests.post(target, data=data, proxies=proxy, timeout=req_timeout, allow_redirects=False, **kwargs)
            return (target, response)

        if isinstance(target, Target) and request_type == "get":
            if hadoop_reporting:
                logger.info("GET requesting %s", target)

            response = requests.get(target.url, proxies=proxy, timeout=req_timeout, allow_redirects=False, **kwargs)
            return (target, response)

        if isinstance(target, Target) and request_type == "post":

            if hadoop_reporting:
                logger.info("POST requesting %s" % target)
            response = requests.post(target.url, data=data, proxies=proxy, timeout=req_timeout, allow_redirects=False, **kwargs)
            return (target, response)

    except:
        #threads suck at exceptions (or I do?), use this to mark failure
        return (target, "__PNK_REQ_FAILED")
