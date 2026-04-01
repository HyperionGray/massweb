""" Helper functions for matching parts of strings """

import logging
from typing import List

from bs4 import BeautifulSoup

logger = logging.getLogger("vuln_checks")


def match_string(str_in: str, match: str) -> bool:
    """ Check if a string is found in another string.

    str_in  Input string.
    match   String to find in str_in.

    returns True if a match is found and False if no match is found.
    """
    if match in str_in:
        return True
    else:
        return False


def match_strings(str_in: str, match_list: List[str]) -> bool:
    """ Check if any of a list of strings is found in another string.

    str_in      input string.
    match_list  list of strings to find in str_in.

    returns     True if a match is found and False if no match is found.
    """
    for match in match_list:
        if match in str_in:
            return True
    return False


def parse_match(str_in: str, tag: str, match: str) -> bool:
    """ Parse HTML string for a particular tag and attempt to find a matching
        string in the contents of that tag.

    str_in  input string.
    tag     html tag to parse for.
    match   string to match against the contents of the tags.

    returns True if a match is found and False if no match is found.
    """
    # Use html.parser instead of html5lib because html5lib strips script content
    for element in BeautifulSoup(str_in, 'html.parser').find_all(tag):
        try:
            element_text = element.get_text()
            if match_string(element_text, match):
                return True
        except Exception:
            logger.debug("Failed while parsing response content for tag '%s'",
                         tag, exc_info=True)
            continue
    return False
