#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import traceback
from urlparse import urlparse
from bs4 import BeautifulSoup, SoupStrainer
from massweb.mass_requests.mass_request import MassRequest
from massweb.pnk_net.find_post import normalize_link
from massweb.targets.crawl_target import CrawlTarget
from massweb.pnk_net.find_post import find_post_requests
import codecs
import logging
from logging import StreamHandler
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
mc_logger = logging.getLogger('MassCrawlLogger')
mc_logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

class MassCrawl(object):

    def __init__(self, seeds = [], add_seeds_to_scope = True):

        mc_logger.info("Insantiating MassCrawl object")
        self.seeds = seeds
        self.domains = []
        self.posts_identified = []

        for seed in seeds:
            domain_raw = urlparse(seed).netloc
            if ":" in domain_raw:
                domain = domain_raw.split(":")[0]
            else:
                domain = domain_raw

            self.domains.append(domain)

        self.targets = []
        for seed in seeds:
            ct = CrawlTarget(seed)
            self.add_target(ct)

    def get_domain_from_url(self, url):

        domain_raw = urlparse(url).netloc
        if ":" in domain_raw:
            domain = domain_raw.split(":")[0]
        else:
            domain = domain_raw

        return domain

    def add_to_scope_from_url(self, url):

        domain = self.get_domain_from_url(url)
        self.add_to_scope(domain)

    def add_to_scope(self, domain):

        if domain not in self.domains:
            self.domains.append(domain)

    def in_scope(self, url):

        domain = self.get_domain_from_url(url)

        if domain in self.domains:
            return True
        else:
            return False

    def add_target(self, target):

        if target not in self.targets:
            self.targets.append(target)

    def parse_response(self, response, stay_in_scope = True, max_links = 10):
        #implement max_links

        response_text = response.text
        url = response.url

        link_c = 0
        
        for link in BeautifulSoup(response_text, 'html.parser', parse_only=SoupStrainer(['a', 'img', 'script', 'link'])):

            #stop spitting back links if max links reached
            if link_c > max_links:
                raise StopIteration

            href = None
            if link.get('href'):
                href = link.get('href')

            elif link.get('src'):
                href = link.get('src')

            if href and not href.startswith("mailto:"):

                try:
                    link_normed = normalize_link(href, url)["norm_url"]
                    if stay_in_scope:

                        if self.in_scope(link_normed):

                            link_c += 1
                            yield link_normed

                    else:
                        link_c += 1
                        yield link_normed

                except:
                    try:
                        mc_logger.info("Handled exception: ")
                        traceback.print_exc()
                    except:
                        mc_logger.warn("Couldn't print exception in MassCrawl.parse_response")

                    continue

    def fetch(self, num_threads = 10, time_per_url = 10, request_timeout = 10, proxy_list = [{}]):
        """Fetch URLs and append them to the seed list"""
        
        self.mreq = MassRequest(num_threads = num_threads, time_per_url = time_per_url, request_timeout = request_timeout, proxy_list = proxy_list)
        unfetched_targets = [unfetched_target for unfetched_target in self.targets if unfetched_target.status == "unfetched"]

        for ut in unfetched_targets:
            mc_logger.info(u"Fetching " + unicode(ut))

        #!note this only fetches via GET, doesn't submit forms for more links
        self.mreq.get_targets(self.targets)
        self.results = self.mreq.results

        for target in self.targets:
            target.status = "fetched"

    def parse(self, stay_in_scope = True, max_links = 10, max_parse_size = 5000000):

        for result in self.results:

            try:
                #skip 400s and strings (i.e. failed requests)
                mc_logger.info(u"Attempting to parse " + unicode(result[0]))

                response = result[1]
                response.raise_for_status()
                
                url_path = urlparse(unicode(result[0])).path

                if not "content-type" in response.headers:
                    mc_logger.info(u"No Content Type header, not parsing " + unicode(result[0]))
                    continue

                else:
                    mc_logger.info(u"Content type is of type " + unicode(response.headers["content-type"]) + u": " + unicode(result[0]))
                    if not "text/html" in response.headers["content-type"]:
                        mc_logger.info(u"Content type is of type " + unicode(response.headers["content-type"]) + u" NOT parsing: " + unicode(result[0]))
                        continue

                if "content-length" in response.headers:
                    mc_logger.info(u"Content length is " + unicode(response.headers["content-length"]) + u": " + unicode(result[0]))
                    if int(response.headers["content-length"]) > max_parse_size:
                        mc_logger.info(u"Content length is " + unicode(response.headers["content-length"]) + u" NOT parsing: " + unicode(result[0]))
                        continue

                else:
                    if sys.getsizeof(response.text) > max_parse_size:
                        mc_logger.info(u"URL returned response that was deemed too big to parse, skipping: " + unicode(result[0]))
                        continue

                post_request_targets = find_post_requests(response.url, response.text)
                for target_post in post_request_targets:

                    ct_post = CrawlTarget(target_post.url)
                    ct_post.__dict__ = target_post.__dict__
                    ct_post.status = "unfetched"
                    self.add_target(ct_post)

                links = self.parse_response(response, stay_in_scope = stay_in_scope, max_links = max_links)
                for link in links:
                    ct_link = CrawlTarget(unicode(link))
                    self.add_target(ct_link)

            except:

                try:
                    mc_logger.info("Handled exception: ")
                    traceback.print_exc()

                except:
                    mc_logger.warn("Couldn't print exception in MassCrawl.parse")

            mc_logger.info(u"Finished attempted parsing for " + unicode(result[0]))

    def crawl(self, 
              depth = 3, 
              num_threads = 10, 
              time_per_url = 10, 
              request_timeout = 10, 
              proxy_list = [{}], 
              stay_in_scope = True, 
              max_links = 10, 
              max_parse_size = 5000000):

        for _ in range(depth):

            mc_logger.info("Entering the fetch phase at depth %s" % str(depth))
            self.fetch(num_threads = num_threads, time_per_url = time_per_url, request_timeout = request_timeout, proxy_list = proxy_list)
            mc_logger.info("Entering the parse phase at depth %s" % str(depth))
            self.parse(max_links = max_links, stay_in_scope = stay_in_scope, max_parse_size = max_parse_size)

if __name__ == "__main__":

    seeds = ["http://www.hyperiongray.com", "http://course.hyperiongray.com/vuln1", "http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/",
#             "http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E", "http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=1",
#             "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1", "http://www.dobrevsource.org/index.php?id=1",
             u"http://JP納豆.例.jp/", u"http://prisons.ir/", u"http://www.qeng.ir/", u"http://www.girlsworker.jp/shiryo.zip"]

    seeds_uni = [unicode(seed) for seed in seeds]

    mc = MassCrawl(seeds = seeds_uni)
    mc.crawl(num_threads = 30, time_per_url = 5, request_timeout = 3, proxy_list = [{}])

#    f = open("out", "a")
#    for t in mc.targets:
#        f.write(t.url)

#    for t in mc.targets:
#        with codecs.open("test_output", "a", "utf-8") as temp:
#            temp.write(t.url)
#            temp.write("\n")
#            
#    print len(mc.targets)
