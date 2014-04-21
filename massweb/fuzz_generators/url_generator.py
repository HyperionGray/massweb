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

def replace_param_value(url, param, replacement_string):
    '''Replace a parameter in a url with another string. Returns
    a fully reassembled url as a string.'''

    url_parsed = urlparse(url)
    query_dic = parse_qs(url_parsed.query)
    query_dic[param] = replacement_string

    #this incidentally will also automatically url-encode the payload (thanks urlencode!)
    query_reassembled = urlencode(query_dic, doseq = True)

    #3rd element is always the query, replace query with our own
    url_list_parsed = list(url_parsed)
    url_list_parsed[4] = query_reassembled
    url_parsed_q_replaced = tuple(url_list_parsed)
    url_reassembled = urlunparse(url_parsed_q_replaced)

    return url_reassembled

def generate_fuzzy_urls(url, payloads):

    parsed_url = urlparse(url)
    parsed_url_query = parsed_url.query
    url_q_dic = parse_qs(parsed_url_query)

    fuzzy_urls = []
    for query_param, query_val in url_q_dic.iteritems():

        for payload in payloads:
            fuzzy_urls.append(replace_param_value(url, query_param, str(payload)))

    return fuzzy_urls
