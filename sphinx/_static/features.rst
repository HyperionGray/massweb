Current Feature Set
===================

* MassRequests library can be used to request large amounts of GET or POST requests in a short amount of time and with a hard timeout
    * Threading is handled transparently, you don't have to write any multi-threaded code
    * Support for a &quot;tcp timeout&quot; and a &quot;hard timeout&quot; (i.e. the absolute max amount of time to spend per URL) allowing one to calculate the upper bound timeline for fetching all desired data
    * Support for proxy rotation
* Automatically discover valid POST requests, and add to target set
* Scan web apps for vulnerabilities via GET and POST
    * Threading is handled transparently, you don't have to write any multi-threaded code
    * Support for hard timeouts
    * Configurable payload sets and vulnerability checks
