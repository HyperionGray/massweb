
"""
>>> from massweb.mass_requests.mass_request import MassRequest
>>> urls_to_fetch = [u"http://www.hyperiongray.com", u"http://course.hyperiongray.com/vuln1/", u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/"]
>>> mr = MassRequest()
>>> mr.get_urls(urls_to_fetch)
>>> for target, response in mr.results:
    ...     print target, response
    ...
    http://www.hyperiongray.com <Response [200]>
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/ <Response [200]>
    http://course.hyperiongray.com/vuln1/ <Response [200]>
"""


from massweb.mass_requests.mass_request import MassRequest
urls_to_fetch = [u"http://www.hyperiongray.com", u"http://course.hyperiongray.com/vuln1/", u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/"]
mr = MassRequest()
mr.get_urls(urls_to_fetch)
for target, response in mr.results:
    print target, response

