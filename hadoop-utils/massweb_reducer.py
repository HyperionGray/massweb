import json
import sys
import urlparse

previous_domain  = None
previous_result_dic = None
previous_domain_vuln_list = []

for line in sys.stdin:

    line = line.strip()
    domain_in, result_dic_in = line.split("\t")
    result_dic_in = json.loads(result_dic_in)

    if not previous_domain:
        previous_domain = domain_in
        previous_result_dic = result_dic_in
        previous_domain_vuln_list = []
        continue

    if domain_in == previous_domain:
        previous_domain_vuln_list.append(previous_result_dic)
    else:
        previous_domain_vuln_list.append(previous_result_dic)
        print previous_domain + "\t" +  json.dumps(previous_domain_vuln_list)
        previous_domain_vuln_list = []
        
    previous_domain = domain_in
    previous_result_dic = result_dic_in

if previous_domain == domain_in:
    previous_domain_vuln_list.append(previous_result_dic)
    print previous_domain + "\t" + json.dumps(previous_domain_vuln_list)
