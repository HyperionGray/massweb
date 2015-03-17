# -*- coding: utf-8 -*-
""" MassCrawl is the crawler/spider part of MassWeb """

import sys
from urlparse import urlparse
import codecs
import logging

from bs4 import BeautifulSoup, SoupStrainer

from requests.exceptions import HTTPError

from massweb.targets.crawl_target import CrawlTarget
from massweb.mass_requests.mass_request import MassRequest
from massweb.mass_requests.response_analysis import parse_worthy
from massweb.pnk_net.find_post import normalize_link
from massweb.pnk_net.find_post import find_post_requests

logging.basicConfig(format='%(asctime)s %(name)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('MassCrawlLogger')
logger.setLevel(logging.DEBUG)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)


class MassCrawl(object):

    def __init__(self, seeds=[], add_seeds_to_scope=True):
        logger.info("Insantiating MassCrawl object")
        self.seeds = seeds
        self.domains = []
        self.posts_identified = []
        self.targets = []
        self.results = []
        self.mreq = None
        self.add_seeds_to_scope(seeds)
        self.add_seeds_to_targets(seeds)

    def add_seeds_to_scope(self, seeds):
        for seed in seeds:
            self.add_to_scope_from_url(seed)

    def add_seeds_to_targets(self, seeds):
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
        return domain in self.domains

    def add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)

    def parse_response(self, response, stay_in_scope=True, max_links=10):
        links = []
        for tag in BeautifulSoup(response.text, 'html.parser',
                                 parse_only=SoupStrainer(['a', 'img', 'script',
                                                          'link'])):
            # stop finding links if max links reached
            if len(links) <= max_links:
                link = self.parse_tag(tag, response, stay_in_scope)
                if link:
                    links.append(link)
        return links

    def parse_tag(self, tag, response, stay_in_scope):
        href = None
        if tag.get('href'):
            href = tag.get('href')
        elif tag.get('src'):
            href = tag.get('src')
        if href and not href.startswith("mailto:"):
            link_normed = normalize_link(href, response.url)["norm_url"]
            if stay_in_scope:
                if self.in_scope(link_normed):
                    return link_normed
            else:
                return link_normed

    def dedupe_targets(self):
        seen_hashes = []
        for target in self.targets:
            target_hash = hash(target)
            if target_hash in seen_hashes:
                self.targets.pop(self.targets.index(target))
                logger.warn("Found duplicate target: %s", target)
            else:
                seen_hashes.append(target_hash)

    def filter_targets_by_scope(self):
        #FIXME: !in large-scale crawls, there's some out of scope posts,
        #   this is a hack to stop that, real issue should be found
        #   and resolved
        logger.info("Filtering targets by scope")
        for target in self.targets:
            if not self.in_scope(target.url):
                self.targets.pop(self.targets.index(target))
                logger.warn("Target filtered out that was not in scope: %s",
                               target.url)

    def fetch(self, num_threads=10, time_per_url=10, request_timeout=10,
              proxy_list=[{}]):
        """Fetch URLs and append them to the seed list"""
        self.mreq = MassRequest(num_threads=num_threads,
                                time_per_url=time_per_url,
                                request_timeout=request_timeout,
                                proxy_list=proxy_list,
                                hadoop_reporting=True)
        unfetched_targets = [unfetched_target
                             for unfetched_target in self.targets
                             if unfetched_target.status == "unfetched"]
        for ut in unfetched_targets:
            logger.info("Fetching %s", ut)
        # NB: this only fetches via GET, doesn't submit forms for more links
        self.mreq.get_targets(self.targets)
        self.results = self.mreq.results
        for target in self.targets:
            target.status = "fetched"

    def parse(self, stay_in_scope=True, max_links=10):
        for target, response in self.results:
            # skip 40X replies and strings (i.e. failed requests)
            logger.info("Attempting to parse %s", target)
            try:
                response.raise_for_status()
            except (HTTPError, AttributeError) as exc:   # only exception type we care about from requests.Response
                logger.debug("Failed request.", exc_info=True)
                continue
            if parse_worthy(response, content_type_match="text/html",
                            hadoop_reporting=True):
                logger.info("pase_worthy function tells us to parse")
            else:
                logger.info("pase_worthy function tells us not to try"
                            " parsing")
                continue
            logger.info("Finding post requests on page %s", response.url)
            #FIXME: !this doesn't stay in scope?
            post_request_targets = find_post_requests(target=response.url,
                                                      response_text=response.text)
            for target_post in post_request_targets:
                ct_post = CrawlTarget(target_post.url)
                ct_post.__dict__ = target_post.__dict__
                ct_post.status = "unfetched"
                self.add_target(ct_post)
            links = self.parse_response(response, stay_in_scope=stay_in_scope,
                                        max_links=max_links)
            for link in links:
                ct_link = CrawlTarget(unicode(link))
                self.add_target(ct_link)
            if stay_in_scope:
                self.filter_targets_by_scope()

            logger.info("Finished attempted parsing for %s", target)

    def crawl(self,
              depth=3,
              num_threads=10,
              time_per_url=10,
              request_timeout=10,
              proxy_list=None,
              stay_in_scope=True,
              max_links=10, dedupe=True):

        for _ in range(depth):
            logger.info("Entering the fetch phase at depth %d", depth)
            self.fetch(num_threads=num_threads, time_per_url=time_per_url,
                       request_timeout=request_timeout, proxy_list=proxy_list or None)
            logger.info("Entering the parse phase at depth %d", depth)
            self.parse(max_links=max_links, stay_in_scope=stay_in_scope)
            if dedupe:
                self.dedupe_targets()
            if stay_in_scope:
                self.filter_targets_by_scope()
