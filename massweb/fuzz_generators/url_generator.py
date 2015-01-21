""" Some helpers to generate URLs for fuzzing. """

from urlparse import parse_qs, urlparse, urlunparse
from urllib import urlencode


def replace_param_value(url, param, replacement_string):
    """ Replace a parameter in a url with another string. Returns
    a fully reassembled url as a string.

    url                 URL to mangle as string.
    param               Parameter in url to replace the value of.
    replacement_string  String to replace the value of param in url with.
    """
    url_parsed = urlparse(url)
    query_dic = parse_qs(url_parsed.query)
    query_dic[param] = replacement_string
    # this incidentally will also automatically url-encode the payload
    #  (thanks urlencode!)
    query_reassembled = urlencode(query_dic, doseq=True)
    # 3rd element is always the query, replace query with our own
    #FIXME: Why not do this with the urlparse object?
    url_list_parsed = list(url_parsed)
    url_list_parsed[4] = query_reassembled
    url_parsed_q_replaced = tuple(url_list_parsed)
    url_reassembled = urlunparse(url_parsed_q_replaced)
    return url_reassembled


def generate_fuzzy_urls(url, payloads):
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
            fuzzy_urls.append(replace_param_value(url, query_param,
                                                  str(payload)))
    return fuzzy_urls
