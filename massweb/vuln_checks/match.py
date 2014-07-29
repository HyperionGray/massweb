import sys
import requests
import traceback
from bs4 import BeautifulSoup, SoupStrainer

def match_string(_input, match):

    if match in _input:
        return True

    else:
        return False

def match_strings(_input, match_list):

    for match in match_list:
        if match in _input:
            return True

    return False

def parse_match(_input, tag, match):

    if sys.getsizeof(_input) > 4097152:
        sys.stderr.write("Input is too big to parse, skipping it")
        return False

    for script in BeautifulSoup(_input, 'html5lib', 
                                parse_only = SoupStrainer([tag])):

        try:
            script_text = script.get_text()
            if match in script_text:
                return True

        except:
            continue

    return False

if __name__ == "__main__":

    x = requests.get("http://www.punkspider.org/lists/whitelist.list").text
    print parse_match(x, "script", "t")
