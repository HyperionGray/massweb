import unittest

from requests import Response

from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload
from massweb.targets.target import Target


class TestWebFuzzerOffline(unittest.TestCase):
    def _make_response(self, url, body):
        response = Response()
        response.status_code = 200
        response.url = url
        response.encoding = "utf-8"
        response._content = body.encode("utf-8")
        response.headers = {
            "content-type": "text/html; charset=utf-8",
            "content-length": str(len(response._content)),
        }
        return response

    def test_fuzz_offline_xss(self):
        target = Target("http://example.test/?q=1&x=2")
        payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"])

        wf = WebFuzzer(
            targets=[target],
            num_threads=1,
            time_per_url=1,
            request_timeout=1,
            proxy_list=[{}],
            hadoop_reporting=False,
        )
        wf.add_payload(payload)
        wf.generate_fuzzy_targets()

        def fake_request_targets(targets):
            wf.mreq.results = [
                (t, self._make_response(t.url, "<html><script>alert(31337)</script></html>"))
                for t in targets
            ]

        wf.mreq.request_targets = fake_request_targets

        results = wf.fuzz()
        self.assertEqual(len(results), len(wf.fuzzy_targets))
        self.assertTrue(all(r.result_dic.get("xss") is True for r in results))

