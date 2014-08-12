from massweb.payloads.payload import Payload
from massweb.targets.target import Target

class CrawlTarget(Target):

    def __init__(self, url, data = None, ttype = "get", status = "unfetched"):

        super(CrawlTarget, self).__init__(url, data = data, ttype = ttype)
        self.status = status

if __name__ == "__main__":

    ct = CrawlTarget("dddd")

    print ct.ttype
