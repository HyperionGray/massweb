""" """
import codecs
import logging
import sys

from multiprocessing import Pool
from sets import Set

from massweb.pnk_net.pnk_request import pnk_request_raw
from massweb.pnk_net.find_post import find_post_requests
from massweb.targets.target import Target

logging.basicConfig(format='%(asctime)s %(name)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('MassRequest')
logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)


class MassRequest(object):
    """ """

    def __init__(self, num_threads=10, time_per_url=10, request_timeout=10,
                 proxy_list=None, hadoop_reporting=False):
        """
        num_threads         Number of threads to run in seconds. Default 10.
        time_per_url        Seconds to spend on each URL. Default 10.
        request_timeout     Seconds to wait before assuming the request has timed out. Default 10.
        proxy_list=None     List of proxies to cycle through. Default None.
        hadoop_reporting    Turn reporting for hadoop on if True and off is False. Default False.
        """
        self.num_threads = num_threads
        self.time_per_url = time_per_url
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list or [{}]
        self.results = []
        #FIXME: empty fixme #!
        self.finished = []
        self.attempted = []
        self.identified_post_requests = []
        self.hadoop_reporting = hadoop_reporting
        self.ttype_func_callback = {'get': (pnk_request_raw, self.add_to_finished, 'get'),
                'post': (pnk_request_raw, self.add_to_finished, 'post'),
                'identify_post': (find_post_requests, self.add_to_identified_post, 'post')}
        if self.hadoop_reporting:
            logger.info("Instantiated MassRequest object with %d threads and %d time per url",
                        num_threads, time_per_url)

    @property
    def urls_attempted(self):
        return [x.url for x in self.attempted]

    @property
    def urls_finished(self):
        return [x.url for x in self.finished]

    @property
    def targets_attempted(self):
        return self.attempted

    @property
    def targets_finished(self):
        return self.finished

    def add_to_identified_post(self, requests):
        """" Add targets that have post inputs to the list of said targets """
        for request in requests:
            self.identified_post_requests.append(request)

    def add_to_finished(self, x):
        """ Add finished requests to the list of finished requests """
        self.finished.append(x[0])
        self.results.append(x)

    def request_targets(self, targets):
        ret = self._check_method_input(targets, self._arg_sample_list,'targets', list)
        if ret: raise ret
        self.handle_targets(targets=targets, action="get")
        self.handle_targets(targets=targets, action="post")

    def get_post_requests_from_targets(self, targets):
        """ Find targets that have post inputs for later use """
        ret = self._check_method_input(targets, self._arg_sample_list,'targets', list)
        if ret: raise ret
        self.handle_targets(targets=targets, action="identify_posts")

    def post_urls(self, urls_and_data):
        """ Try to send post requests to all the listed (url, data) tuples. """
        ret = self._check_method_input(urls_and_data, self._arg_sample_list,'urls_and_data', basestring)
        if ret: raise ret
        targets = [self.to_target(x, "post") for x in urls_and_data]
        self.handle_targets(targets=targets)

    def post_targets(self, targets):
        """ Try to send post requests to all the listed targets. """
        ret = self._check_method_input(targets, self._arg_sample_list,'targets', list)
        if ret: raise ret
        self.handle_targets(targets=targets)

    def get_targets(self, targets):
        """ Try to send get requests to all the listed targets. """
        ret = self._check_method_input(targets, self._arg_sample_list,'targets', list)
        if ret: raise ret
        self.handle_targets(targets=targets)

    def get_urls(self, urls):
        """ Try to send gett requests to all the listed urls. """
        ret = self._check_method_input(urls, unicode,'urls', basestring)
        if ret: raise ret
        targets = [self.to_target(x, "get") for x in urls]
        self.handle_targets(targets=targets)

    def handle_targets(self, targets=None, action=None):
        """ Handle targets """
        if not targets: return None
        if not action:
            action = targets[0].ttype
        # get timeout for process
        # UNUSED
        timeout = self.determine_timeout(self.time_per_url, targets)
        # Load up the process pool
        self.pool = Pool(processes=self.num_threads)
        self.proc_results = []
        # for each target in targets ...
        for target in targets:
            # Append it to the list of attempted urls
            self.attempted.append(target)
            proc = self.create_process(target, action)
            # Stash the process handle for later use
            self.proc_results.append(proc)
        if self.hadoop_reporting:
            logger.info("Giving each URL %d seconds to respond",
                        self.time_per_url)
        self.collect_target_results()

    def collect_target_results(self):
        for result in self.proc_results:
            try:
                result.get(timeout=self.time_per_url)
            except: #FIXME: Add exception types
                if self.hadoop_reporting:
                    #logger.error(traceback.format_exc()) #FIXME: is this hadoop safe?
                    logger.info("Thread timed out or threw exception, killing it and replacing it")
                self.terminate_pool()
        self.terminate_pool()
        self.list_diff()

    def terminate_pool(self):
        self.pool.terminate()
        self.pool.join()

    def create_process(self, target, action):
        # create a new process to process the URL
        function, callback, req_type = self.ttype_func_callback[action]
        proc = self.pool.apply_async(func=function,
                args=(target, req_type, None, self.request_timeout,
                    self.proxy_list,
                    self.hadoop_reporting),
                callback=callback)
        return proc

    def list_diff(self):
        list_diff = Set(self.attempted).difference(Set(self.finished))
        self.clear_lists()
        for url in list_diff:
            logger.debug("URL %s got timeout", url)
            self.results.append((url, "__PNK_THREAD_TIMEOUT"))

    def clear_lists(self):
        self.attempted = self.finished = self.identified_post_requests = []

    def determine_timeout(self, time_per_item=None, items=None):
        time_per_item = time_per_item or self.time_per_url
        try:
            timeout = float(time_per_item * len(items))
        except:
            item_num = 0
            for item in items:
                item_num += 1
            items.seek(0)

    def to_target(self, item, request_type):
        if isinstance(item, Target):
            return item
        elif isinstance(item, basestring):
            return Target(unicode(item), request_type)
        elif isinstance(item, list) or isinstance(item, tuple):
            url, data = item
            return Target(url, request_type, data)

    def _check_method_input(self, args, sampler, arg_name, arg_type):
        if not args:
            return ValueError("arguemnt %s is required" % arg_name)
        if not isinstance(args, arg_type):
            return TypeError("%s of type %s is required." % (arg_name, arg_type.__name__))

    def _arg_sample_list(self, item_list):
        return item_list[0]
