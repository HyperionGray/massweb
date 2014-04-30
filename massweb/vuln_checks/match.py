import requests
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

    for script in BeautifulSoup(_input, 'lxml', 
                                parse_only = SoupStrainer([tag])):

        if match in script.get_text():
            return True

    return False


if __name__ == "__main__":

    x = requests.get("http://www.hyperiongray.com").text
    parse_match(x, "script", "d")
