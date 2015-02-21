"""
>>> from massweb.mass_requests.mass_request import MassRequest
>>> from massweb.targets.target import Target
>>>
>>> target_1 = Target(url=u"http://course.hyperiongray.com/vuln1", data={"password" : "blh123"}, ttype="post")
>>> target_2 = Target(url=u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/", data={"how" : "I'm good thx"}, ttype="post")
>>> target_3 = Target(url=u"http://www.hyperiongray.com/", ttype="get")
>>> targets = [target_1, target_2, target_3]
>>> mr = MassRequest()
>>> mr.request_targets(targets)
>>> for r in mr.results:
...     print r
...
(<massweb.targets.target.Target object at 0x15496d0>, <Response [200]>)
(<massweb.targets.target.Target object at 0x1549650>, <Response [200]>)
(<massweb.targets.target.Target object at 0x1549490>, <Response [200]>)
>>> for target, response in mr.results:
...     print target, response.status_code
...
http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/ 200
http://www.hyperiongray.com/ 200
http://course.hyperiongray.com/vuln1 200
"""

from massweb.mass_requests.mass_request import MassRequest
from massweb.targets.target import Target

target_1 = Target(url=u"http://course.hyperiongray.com/vuln1", data={"password" : "blh123"}, ttype="post")
target_2 = Target(url=u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/", data={"how" : "I'm good thx"}, ttype="post")
target_3 = Target(url=u"http://www.hyperiongray.com/", ttype="get")
targets = [target_1, target_2, target_3]
mr = MassRequest()
mr.request_targets(targets)
for r in mr.results:
    print r
for target, response in mr.results:
    print target, response.status_code

