
import codecs
import logging
import sys

import requests

from massweb.targets.target import Target
from massweb.proxy_rotator.proxy_rotate import get_random_proxy

logging.basicConfig(format='%(asctime)s %(name)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('pnknet')
logger.setLevel(logging.DEBUG)
# In Python 3, sys.stdin/stderr are already text streams with encoding
if hasattr(sys.stdin, 'buffer'):
    sys.stdin = codecs.getreader('utf-8')(sys.stdin.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)

#FIXME: define in central const module
IDENTIFY_POSTS = 'identify_post'
GET = 'get'
POST = 'post'


def pnk_request_raw(target, request_type=GET, data=None, req_timeout=5,
                    proxy_list=None, hadoop_reporting=False, **kwargs):
    if proxy_list is not None:
        proxy = get_random_proxy(proxy_list)
    else:
        proxy = {}
    logger.debug("pnk_request_raw input target type: %s", target.__class__.__name__)
    try:
        if isinstance(target, str):
            url = target.strip()
        elif isinstance(target, Target):
            url = target.url
            if target.data and data:
                logger.error("%s.data and data are both specified using Target.data.", target.__class__.__name__)
                logger.debug("%s.data %s; data: %s", target.__class__.__name__, target.data, data)
            data = target.data or data
        else:
            raise TypeError("target must be an instance of Target or str not: %s", target.__class__.__name__)
        if request_type == GET:
            if hadoop_reporting:
                logger.info("GET requesting %s", target)
            response = requests.get(url, proxies=proxy,
                                    timeout=req_timeout,
                                    allow_redirects=False, **kwargs)
        elif request_type == POST:
            logger.debug(" POST Data: %s", data)
            if hadoop_reporting:
                logger.info("POST requesting %s", target)
            response = requests.post(url, data=data, proxies=proxy,
                                     timeout=req_timeout,
                                     allow_redirects=False, **kwargs)
        else:
            raise ValueError("request_type must be either %s or %s", GET, POST)
        logger.debug("pnk_request_raw output target type: %s", target.__class__.__name__)
        return (target, response)
    except:
        # Threads suck at exceptions (or I do?), use this to mark failure
        logger.debug("pnk_request_raw output target type: %s", target.__class__.__name__)
        return (target, "__PNK_REQ_FAILED")
