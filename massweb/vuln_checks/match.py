""" Helper functions for matching parts of strings """

import logging

from bs4 import BeautifulSoup

logger = logging.getLogger("vuln_checks")


def match_string(str_in, match):
    """ Check if a string is found in another string.

    str_in  Input string.
    match   String to find in str_in.

    returns True if a match is found and False if no match is found.
    """
    if match in str_in:
        return True
    else:
        return False


def match_strings(str_in, match_list):
    """ Check if any of a list of strings is found in another string.

    str_in      input string.
    match_list  list of strings to find in str_in.

    returns     True if a match is found and False if no match is found.
    """
    for match in match_list:
        if match in str_in:
            return True
    return False


def parse_match(str_in, tag, match):
    """ Parse HTML string for a particular tag and attempt to find a matching
        string in the contents of that tag.

    Currently is hardcoded for 'script' tags.

    str_in  input string.
    tag     html tag to parse for.
    match   string to match against the contents of the tags.

    returns True if a match is found and False if no match is found.
    """
    #FIXME: tag is unused should it be used in place of 'script'? PNKTHR-52
    # Use html.parser instead of html5lib because html5lib strips script content
    for script in BeautifulSoup(str_in, 'html.parser').find_all(tag):
        try:
            script_text = script.get_text()
            if match_string(script_text, match):
                return True
        except: #FIXME: specify exception types
            logger.debug("Failed while parsing response content for tag '%s'",
                         tag, exc_info=True)
            continue
    return False
