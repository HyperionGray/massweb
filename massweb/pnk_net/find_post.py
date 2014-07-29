import os 
from bs4 import BeautifulSoup, SoupStrainer
import sys
from urlparse import urlparse, urlunparse
import traceback
from requests.exceptions import ConnectionError
import urllib
import requests
from massweb.targets.fuzzy_target import FuzzyTarget
from massweb.targets.target import Target
from massweb.pnk_net.pnk_request import pnk_request_raw
from urlparse import urljoin

def normalize_link(url_to_normalize, current_page_url):

    #not quite, doesn't include path in normalization, gets paths wrong

    cp_scheme, cp_netloc, cp_path, cp_params, cp_query, cp_fragment = urlparse(current_page_url)

    parsed_url_to_normalize = urlparse(url_to_normalize)
    scheme, netloc, path, params, query, fragment = urlparse(url_to_normalize)

    if not parsed_url_to_normalize.scheme or not parsed_url_to_normalize.netloc:
        full_url = urljoin(current_page_url, url_to_normalize)
    else:
        full_url = url_to_normalize

    return {"norm_url" : full_url, "netloc" : netloc}

def find_post_requests(url, response_text = None, strict_scope = True):

    if not response_text:
        response_text = pnk_request_raw(url)[1].text

    if strict_scope:
        url_host = urlparse(url).netloc

    post_requests = []
    for form in BeautifulSoup(response_text, 'html.parser', parse_only=SoupStrainer('form')):

        norm_link_dic = normalize_link(form["action"], url)
        norm_url = norm_link_dic["norm_url"]
        form_host = norm_link_dic["netloc"]

        if strict_scope:

            #if form explicitly specifies host that doesn't match current host
            #if doesn't specify host, gets normalized to host so assumed to match
            if form_host and url_host != form_host:
                #print "no host match"
                continue

        listform = ["text", "radio", "checkbox", "password", "file", "image", "hidden"]
        _input = form.findAll('input', {'type' : listform})

        post_data = {}
        for elem in _input:
            input_name = elem["name"]
            try:
                value = urllib.quote_plus(elem["value"])
            except:
                value = ""

            post_data[input_name] = value

        target_post = Target(norm_url, data = post_data, ttype = "post")
        post_requests.append(target_post)

    return post_requests

if __name__ == "__main__":

#    find_post_requests("http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=ddd")

#    for p in find_post_requests("http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=ddd", strict_scope = True):
#        print p

    for p in find_post_requests("http://course.hyperiongray.com/vuln1"):
        print p, p.data

    for p in find_post_requests("http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/"):
        print p, p.data
