""" CrawlTarget: MassCrawl adapted Target type """

from massweb.targets.target import Target

class CrawlTarget(Target):
    """ Target type which addes the status property to allow MassCrawl to keep
        track of it's state. """

    def __init__(self, url, data=None, ttype="get", status="unfetched"):
        """ Initialize CrawlTarget object:
            url        str of the location of the target.
            data       dict of parameters to pass via POST request. Default None.
            ttype      str of HTTP request type. Default "get".
            status     str of status assigned by MassCrawl. Default "unfetched". """
        super(CrawlTarget, self).__init__(url, data=data, ttype=ttype)
        self.status = status
