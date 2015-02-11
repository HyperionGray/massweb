""" Some helpers to generate URLs for fuzzing. """

from urlparse import parse_qs, urlparse, urlunparse
from urllib import urlencode

import logging
logger = logging.getLogger("url_generator")
logger.setLevel(logging.DEBUG)

def append_to_param(url, param, value):
    """ Replace a parameter in a url with another string.

    Return a fully reassembled url as a string.

    url                 URL to mangle as string.
    param               Parameter in url to replace the value of.
    value               String to replace the value of param in url with.
    """
    # for the purposes of maintaining consistent interfaces
    return _update_query(url, param, value, append=True)


def replace_param_value(url, param, replacement_string):
    """ Replace a parameter in a url with another string.

    Return a fully reassembled url as a string.

    url                 URL to mangle as string.
    param               Parameter in url to replace the value of.
    replacement_string  String to replace the value of param in url with.
    """
    # for the purposes of maintaining consistent interfaces
    return _update_query(url, param, replacement_string)


def _update_query(url, param, value, append=False):
    """ Insert the provided query int the provided URL.

    url
    param
    value
    append

    This incidentally will also automatically url-encode the payload
    (thanks urlencode!)
    """
    #FIXME: PNKTHR-42 might cause some incorrect query params and keys with utf-8, needs more testing     
    url_parsed = urlparse(url)
    query_dic = parse_qs(url_parsed.query)
    if append:
        query_dic[param] = [x + value for x in query_dic[param]]
    else:
        query_dic[param] = [value for x in query_dic[param]]
    query_dic = _convert_query_to_utf8(query_dic)
    amended_url = _reassemble_url(query_dic, url_parsed)
    return amended_url


def _convert_query_to_utf8(query_dic):
    """ Convert items in dict to utf-8 encoded str. """
    utf8_query_dic = {}
    for k, v in query_dic.iteritems():
        utf8_query_dic[unicode(k).encode('utf-8', 'replace')] = [x.encode('utf-8', 'replace') for x in v]
    return utf8_query_dic


def _reassemble_url(query_dic, url_parsed):
    """ Reassemble the query. """
    query_reassembled = urlencode(query_dic, doseq=True)
    # Reform the list(urlparse) for urlunparse() tuple(scheme, netloc, path, params, query, fragment)
    url_tup = (url_parsed.scheme, url_parsed.netloc, url_parsed.path, url_parsed.params,
               query_reassembled, url_parsed.fragment)
    # Reassemble the URL
    url_reassembled = urlunparse(url_tup)
    return url_reassembled


def geneerate_fuzzy_urls(url, payloads):
    """ Generate a URL suitable for fuzzing, using the suplied payloads.

    url         Base URL.
    payloads    list of Payload objects to apply to url.
    returns     list of URLs as strings
    """
    parsed_url = urlparse(url)
    parsed_url_query = parsed_url.query
    url_q_dic = parse_qs(parsed_url_query)
    fuzzy_urls = []
    for query_param in url_q_dic:
        for payload in payloads:
            furl = replace_param_value(url, query_param, str(payload))
            logger.debug("fuzzy URL: %s, URL: %s, param: %s, payload: %s", furl, url, query_param, payload)
            fuzzy_urls.append(furl)
    return fuzzy_urls


if __name__ == '__main__':
    aurl = "http://www.hyperiongray.com/?q=3234&&q=55555&x=33"
    aparam = "q"
    append_string = "added"
    append_result = append_to_param(aurl, aparam, append_string)
    append_baseline = 'http://www.hyperiongray.com/?q=3234added&q=55555added&x=33'
    print("'%s' == '%s'" % (append_baseline, append_result), append_baseline == append_result)

    rurl = "http://www.hyperiongray.com/?q=3234&&q=55555&x=33"
    rparam = "q"
    replace_string = "replaced" 
    replace_result = replace_param_value(rurl, rparam, replace_string)
    replace_baseline = "http://www.hyperiongray.com/?q=replaced&q=replaced&x=33"
    print("'%s' == '%s'" % (replace_baseline, replace_result), replace_baseline == replace_result)
