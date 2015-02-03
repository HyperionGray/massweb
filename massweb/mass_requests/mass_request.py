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


IDENTIFY_POSTS = 'identify_post'
GET = 'get'
POST = 'post'


class MassRequest(object):
    """ Mass Request class. Applies payloads to targets. """

    def __init__(self, num_threads=10, time_per_url=10, request_timeout=10,
                 proxy_list=None, hadoop_reporting=False):
        """ Initialize this MassRequest object.

        num_threads         Number of threads to run in seconds. Default 10.
        time_per_url        Seconds to spend on each URL. Default 10.
        request_timeout     Seconds to wait before assuming the request has
                                timed out. Default 10.
        proxy_list          List of proxies to cycle through. Default empty.
        hadoop_reporting    Turn reporting for hadoop on if True and off is
                                False. Default False.
        """
        self.num_threads = num_threads
        self.time_per_url = time_per_url
        self.request_timeout = request_timeout
        self.proxy_list = proxy_list or [{}]
        self.results = []
        #FIXME: empty fixme #! PNKTHR-54
        self.finished = []
        self.attempted = []
        self.identified_post_requests = []
        self.hadoop_reporting = hadoop_reporting
        self.ttype_func_callback = {GET: (pnk_request_raw,
                                          self.add_to_finished, 'get'),
                                    POST: (pnk_request_raw,
                                           self.add_to_finished, 'post'),
                                    IDENTIFY_POSTS: (find_post_requests,
                                        self.add_to_identified_post, 'post')}
        if self.hadoop_reporting:
            logger.info("Instantiated MassRequest object with %d threads and"
                        "%d time per url", num_threads, time_per_url)

    @property
    def urls_attempted(self):
        """ Return a list of the URLs attempted. """
        return [x.url for x in self.attempted]

    @property
    def urls_finished(self):
        """ Return a list of URLs that have finished being processed. """
        return [x.url for x in self.finished]

    @property
    def targets_attempted(self):
        """ Return a list of Target objects that this has attempted to
            fuzz.
        """
        return self.attempted

    @property
    def targets_finished(self):
        """ Return a list of Target objects that this has finished fuzzing. """
        return self.finished

    def add_to_identified_post(self, requests):
        """" Add targets that have post inputs to the list of Target objects. """
        for request in requests:
            self.identified_post_requests.append(request)

    def add_to_finished(self, request):
        """ Add finished requests to the list of finished requests """
        self.finished.append(request[0])
        self.results.append(request)

    def request_targets(self, targets):
        """ Apply the payloads of the provided targets. """
        ret = self._check_method_input(targets, 'targets', Target)
        if ret:
            raise ret
        self.handle_targets(targets=targets, action=GET)
        self.handle_targets(targets=targets, action=POST)

    def get_post_requests_from_targets(self, targets):
        """ Find targets that have post inputs for later use. """
        ret = self._check_method_input(targets, 'targets', Target)
        if ret:
            raise ret
        self.handle_targets(targets=targets, action=IDENTIFY_POSTS)

    def post_urls(self, urls_and_data):
        """ Try to send post requests to all the listed (url, data) tuples. """
        ret = self._check_method_input_single(urls_and_data, 'urls_and_data', basestring)
        if ret:
            raise ret
        targets = [self.to_target(x, "post") for x in urls_and_data]
        self.handle_targets(targets=targets)

    def post_targets(self, targets):
        """ Try to send post requests to all the listed targets. """
        ret = self._check_method_input(targets, 'targets', Target)
        if ret:
            raise ret
        self.handle_targets(targets=targets)

    def get_targets(self, targets):
        """ Try to send get requests to all the listed targets. """
        ret = self._check_method_input(targets, 'targets', Target)
        if ret:
            raise ret
        self.handle_targets(targets=targets)

    def get_urls(self, urls):
        """ Try to send gett requests to all the listed urls. """
        ret = self._check_method_input_single(urls, 'urls', basestring)
        if ret:
            raise ret
        targets = [self.to_target(x, "get") for x in urls]
        self.handle_targets(targets=targets)

    def handle_targets(self, targets=None, action=None):
        """ Handle targets. For internal use.

        targets     list of Target objects.
        action      Indicator for what HTTP request type to use. Options found
                        in self.ttype_func_callback, currently:
                        'get'           - process Targets with POST requests
                        'post'          - process Targets with POST requests
                        'identify_post' - look for potential post request
                                            targets.
        """
        # If no targets we have nothing to do so return now.
        if not targets:
            return None
        # If no action specified then pick one from the first target in the
        #   list.
        if not action:
            action = targets[0].ttype
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
        """ Collect results from processes. """
        for result in self.proc_results:
            try:
                result.get(timeout=self.time_per_url)
            except: #FIXME: Add exception types
                if self.hadoop_reporting:
                    logger.info("Thread timed out or threw exception, killing"
                                " it and replacing it", exc_info=True)
                self.terminate_pool()
        self.terminate_pool()
        self.list_diff()

    def terminate_pool(self):
        """ Kill the processes in the pool. """
        self.pool.terminate()
        self.pool.join()

    def create_process(self, target, action):
        """ Create a new process to process a Target.
        
        target      Target object.
        action      See handle_targets for details.
        """
        function, callback, req_type = self.ttype_func_callback[action]
        proc = self.pool.apply_async(func=function,
                args=(target, req_type, None, self.request_timeout,
                    self.proxy_list,
                    self.hadoop_reporting),
                callback=callback)
        return proc

    def list_diff(self):
        """ Find the Target objects that were attempted but not finished and
            set their respnse to __PNK_THREAD_TIMEOUT
        """
        list_diff = Set(self.attempted).difference(Set(self.finished))
        self.clear_lists()
        for url in list_diff:
            logger.debug("URL %s got timeout", url)
            self.results.append((url, "__PNK_THREAD_TIMEOUT"))

    def clear_lists(self):
        """ Set attempted, finished, and identified_post_requests to empty
            lists.
        """
        self.attempted = self.finished = self.identified_post_requests = []

    def to_target(self, item, request_type):
        """ Convert item into a Target object.

        item            URL as a unicode or str, a tuple/list containing a URL
                            and parameters, or a Target object.
        request_type    lowercase get or post specifying the HTTP requast type
        """
        if isinstance(item, Target):
            return item
        elif isinstance(item, basestring):
            return Target(unicode(item), request_type)
        elif isinstance(item, list) or isinstance(item, tuple):
            url, data = item
            return Target(url, request_type, data)

    def _check_method_input(self, arg, arg_name, item_type, type_desc="list"):
        """ Helper that checks the input of a method to ensure the correct
            types and values.

        arg         Argument passed to the parent method.
        arg_name    Name of argument passed as arg for error output.
        item_type   Type of the contents of arg.
        type_desc   Label for the type of the object passed as arg. Default "list".
        """
        if not arg:
            return ValueError("arguemnt %s is required" % arg_name)
        for item in arg:
            if not isinstance(item, item_type):
                return TypeError("%s of type %s is required for %s." % (type_desc, item_type.__name__, arg_name))

    def _check_method_input_single(self, arg, arg_name, item_type=basestring, type_desc="string"):
        """ Helper that checks the input of a method to ensure the correct
            type and value.

        arg         Argument passed to the parent method.
        arg_name    Name of argument passed as arg for error output.
        item_type   Expected type of arg. Default basestring.
        type_desc   Label for the type of the object passed as arg. Default "string".
        """
        if not arg:
            return ValueError("arguemnt %s is required" % arg_name)
        if not isinstance(arg, item_type):
            return TypeError("%s is required to be of type %s." % (arg_name, type_desc))




