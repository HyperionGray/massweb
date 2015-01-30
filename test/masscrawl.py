# coding=utf-8
""" MassCrawl is the crawler/spider part of MassWeb """

import unittest

from massweb.masscrawler.masscrawl import MassCrawl

from masscrawl_utils import baseline_target_urls

# allowed difference (+/-)in length of accumulated_target_urls
MARGIN = 3


class TestMassCrawl(unittest.TestCase):
    """ Sorry excuse for a unittest """

    def setUp(self):
        seeds = ["http://www.hyperiongray.com",
             "http://course.hyperiongray.com/vuln1",
             "http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079"
             "ba3fd1/",
             "http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337"
             "%29%3C%2FScrIpT%3E",
             "http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=1",
             "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;"
             "typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1",
             "http://www.dobrevsource.org/index.php?id=1",
             u"http://JP納豆.例.jp/", "http://prisons.ir/",
             "http://www.qeng.ir/", "http://www.girlsworker.jp/shiryo.zip"]

        self.unicode_seeds = [unicode(seed) for seed in seeds]

    def test_crawl(self):
        crawler = MassCrawl(seeds=self.unicode_seeds)
        crawler.crawl(num_threads=4, time_per_url=5, request_timeout=3,
             proxy_list=[{}])
        accumulated_target_urls = [x.url for x in crawler.targets]
        # The right way
        #self.assertEqual(baseline_target_urls, accumulated_target_urls)
        # The very not right way to work around inconsistent results from live targets
        # assert lists have an overlap that is within MARGIN items of the baseline.
        intersections = set(baseline_target_urls).intersection(accumulated_target_urls)
        intersect_length = len(intersections)
        base_length = len(baseline_target_urls)
        self.assertAlmostEqual(intersect_length, base_length, delta=MARGIN)

    def dump(self, accumulated_targets, file_name):
        """ Dump the target URLs we find to a file for later use 
        Follow up with:
            $ sed -i "s/^.*$/\tu'&'/g" <file_name>
        And then slap 'baseline_targets = [' on the front of the first line and ] on the back of the last line.
        Move to masscrawl_utils.py and import in this file.
        """
        import codecs
        for url in accumulated_target_urls:
            with codecs.open(filename, "a", "utf-8") as temp:
                temp.write(url)
                temp.write("\n")

if __name__ == '__main__':
    unittest.main()
