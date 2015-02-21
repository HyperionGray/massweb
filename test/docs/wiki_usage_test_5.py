from massweb.targets.target import Target
from massweb.fuzzers.web_fuzzer import WebFuzzer
wf = WebFuzzer()
target_1 = Target(u"http://www.hyperiongray.com")
target_2 = Target(u"http://course.hyperiongray.com/vuln1", data = {"password" : "blah"}, ttype = "post")
