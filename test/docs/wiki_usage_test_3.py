
"""
>>> from massweb.mass_requests.mass_request import MassRequest
>>> mr = MassRequest(num_threads=20, time_per_url=2, proxy_list=[{"http": "http://user:password@10.0.0.1:3089/"}, {"http": "http://user:password@10.0.0.2:3089/"}])
>>> mr.get_urls_from_file("../urls.txt")
>>> len(mr.results)
1000
>>> for target, response in mr.results[:10]:
    ...     print target, response
    ...
    http://www.abcselfstorage.co.uk/ __PNK_REQ_FAILED
    http://www.abcskiphirews32.co.uk/ __PNK_REQ_FAILED
    http://abcskateboarding.co.uk/ <Response [404]>
    http://www.abcsalestraining.co.uk/ <Response [200]>
    http://www.abcservice.co.uk/ <Response [200]>
    http://www.abcseaangling.co.uk/ <Response [200]>
    http://www.abcselfdrive.co.uk/ <Response [404]>
    http://www.abcselfstore.co.uk/storage-blogwp-login.php?redirect_to=http%3A%2F%2Fwww.abcselfstore.co.uk%2Fstorage-blog%2Fwp-admin%2F&amp;reauth=1 <Response [404]>
    http://www.abcselfstore.co.uk/abc24-hour-access.html <Response [200]>
"""


from massweb.mass_requests.mass_request import MassRequest
mr = MassRequest(num_threads=20, time_per_url=2, proxy_list=[{"http": "http://user:password@10.0.0.1:3089/"}, {"http": "http://user:password@10.0.0.2:3089/"}])
mr.get_urls_from_file("../urls.txt")
len(mr.results)
for target, response in mr.results[:10]:
    print target, response
