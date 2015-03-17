Features
========

.. include:: subs.rst

Current
_______

* |MassRequest|:

    * The |MassRequest| library can be used to request large amounts of GET or
      POST requests in a short amount of time and with a hard timeout.

    * Threading is handled transparently, you don't have to write any
      multi-threaded code.

    * Both "TCP timeout" and "hard timeout" (i.e. the absolute max
      amount of time to spend per URL) Allowing one to calculate the upper
      bound timeline for fetching all desired data.

    * Proxy rotation to produce an apparent distribution of requests.

    * Automatically discover valid POST requests, and add to target set.

* |MAssCrawl|:

    * Scan web applications for vulnerabilities via GET and POST with |MassCrawl|.

    * Configurable payload sets and vulnerability checks.

    * Support for all the same features found in the |MassRequest| library.

