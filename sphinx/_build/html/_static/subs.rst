


.. MassWeb Classes

.. |BSQLiFuzzer| replace:: :class:`BSQLiFuzzer`
.. |iFuzzer| replace:: :class:`iFuzzer`
.. |WebFuzzer| replace:: :class:`WebFuzzer`
.. |MassCrawl| replace:: :class:`MassCrawl`
.. |MassRequest| replace:: :class:`MassRequest`
.. |BSQLIPayloadGroup| replace:: :class:`BSQLIPayloadGroup`
.. |BSQLIPayload| replace:: :class:`BSQLIPayload`
.. |PayloadGroup| replace:: :class:`PayloadGroup`
.. |Payload| replace:: :class:`Payload`
.. |Payloads| replace:: :class:`Payload` objects
.. |Result| replace:: :class:`Result`
.. |CrawlTarget| replace:: :class:`CrawlTarget`
.. |FuzzyTargetGroup| replace:: :class:`FuzzyTargetGroup`
.. |FuzzyTarget| replace:: :class:`FuzzyTarget`
.. |FuzzyTargets| replace:: :class:`FuzzyTarget` objects
.. |Target| replace:: :class:`Target`
.. |Targets| replace:: :class:`Target` objects
.. |Check| replace:: :class:`Check`
.. |MXICheck| replace:: :class:`MXICheck`
.. |OSCICheck| replace:: :class:`OSCICheck`
.. |SQLICheck| replace:: :class:`SQLICheck`
.. |TravCheck| replace:: :class:`TravCheck`
.. |XPathICheck| replace:: :class:`XPathICheck`
.. |XSSCheck| replace:: :class:`XSSCheck`

.. Thirdparty Classes and Exceptions

.. requests

.. |Response| replace:: :class:`Response`
.. |HTTPError| replace:: :exc:`HTTPError`


.. Built-in Classes and Consts

.. |True| replace:: :const:`True`
.. |False| replace:: :const:`False`
.. |bool| replace:: :class:`bool`
.. |unicode| replace:: :class:`unicode`
.. |int| replace:: :class:`int`
.. |float| replace:: :class:`float`
.. |tuple| replace:: :class:`tuple`
.. |list| replace:: :class:`list`
.. |dict| replace:: :class:`dict`


.. Built-in Exceptions

.. |TypeError| replace:: :exc:`TypeError`
.. |AttributeError| replace:: :exc:`AttributeError`
.. |ValueError| replace:: :exc:`ValueErrror`
.. |NotImplementedError| replace:: :exc:`NotImplementedError`
.. |KeyError| replace:: :exc:`KeyError`


.. Property/parameter descriptions
.. |num_threads-desc| replace:: Number of threads to run in seconds.
.. |time_per_url-desc| replace:: Seconds to spend on each URL.
.. |request_timeout-desc| replace:: Seconds to wait before assuming the request has timed out.
.. |proxy_list-desc| replace:: List of proxies to cycle through.
.. |hadoop_reporting-desc| replace:: Turn reporting for hadoop on if |True| and off is |False|.
.. |ttype-desc| replace:: HTTP request type [GET|POST].
.. |result_dic-desc| replace:: Contains checks types with |bool| values indicating whether vulnerabilities were detected or not.

.. |payload-check_types-desc| replace:: A |list| of check types that the |iFuzzer| will use this |Payload| for.
.. |payload-payload_attributes-desc| replace:: A |dict| of attribute names and values to be passed to the |iFuzzer|.
.. |payload-payload_str-desc| replace:: The payload as a full URL with params etc, or the URL, domain, or IP address for the target.
.. |payloadgroup-payloads-desc| replace:: A |list| of |Payload| objects.

.. |target-fuzzy-params-desc| replace:: ""
.. |target-url-desc| replace:: "Location of the target."
.. |target-post-desc| replace:: "Parameters to pass via the POST request body."
.. |target-ttype-desc| replace:: "HTTP request type."

.. |fuzzytarget-fuzzy_target-desc| replace:: |FuzzyTarget| that has been used.|FuzzyTarget| that has been used.

.. |bsqlipayloadgroup-true_payload-desc| replace::  |BSQLIPayload| for the true SQL statement. It contains ``payload_attributes["truth"]` == True``.
.. |bsqlipayloadgroup-false_payload-desc| replace:: |BSQLIPayload| for the false SQL statement. It contains ``payload_attributes["truth"]` == False``.

.. |massrequest-request-desc-short| replace:: (URL, |Response|)

.. |checkmethodinput-raises-typeerror| replace:: |TypeError| -- If items in |arg| are not instances of |arg-inner-type|.
.. |checkmethodinput-raises-valueerror| replace:: |ValueError| -- When |arg| is not given or is empty.
