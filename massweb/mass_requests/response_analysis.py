"""  """

import codecs
import sys
import logging

import requests
from requests import Response

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('response_analysis.parse_worthy')
logger.setLevel(logging.INFO)
# In Python 3, sys.stdin/stderr are already text streams with encoding
if hasattr(sys.stdin, 'buffer'):
    sys.stdin = codecs.getreader('utf-8')(sys.stdin.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)


def parse_worthy(response, max_parse_size=5000000, content_type_match="text",
                 hadoop_reporting=False):
    """ Determine if it's worth parsing a Response object.

    response            requests.Response object.
    max_parse_size      Maximum length of content in characters. Default 5000000.
    content_type_match  content-type MIME prefix. Default "text" (as in text/html or text/plain).
    hadoop_reporting    Turn on hadoop reporting if True. Default False.

    returns             True if it's worth parsing, False if not.
    raises              TypeError if response is not a requests.Response.
    """
    # Make sure it's the right Type
    _is_response(response)
    # Make sure it has both correct content-type and content-length
    return (_is_correct_content_type(response,
                                    content_type_match,
                                    hadoop_reporting) and
            _is_correct_content_length(response,
                                      max_parse_size,
                                      hadoop_reporting))

def _is_response(response):
    """ Verify response is a requests.Response object.
    
    response            requests.Response object.

    raises              TypeError if response is not a requests.Response.
    """
    if not isinstance(response, Response):
        logger.warn("Response is of type %s with content %s", type(response),
                    response)
        # Die immediately and in a useful way if it's not a response.
        raise TypeError("Response must be of type requests.Response")

def _is_correct_content_type(response, content_type_match, hadoop_reporting):
    """ Verifu that the content-type of respnse is a type we are interested in.

    response            requests.Response object.
    content_type_match  content-type MIME prefix. Default "text" (as in text/html or text/plain).
    hadoop_reporting    Turn on hadoop reporting if True. Default False.
   
    returns     True if it is a correct content-type, False if not.
    """
    if "content-type" not in response.headers:
        if hadoop_reporting:
            logger.info("No Content Type header, not parsing %s", response.url)
        return False
    else:
        logger.info("Content type is of type %s: %s",
                    response.headers["content-type"], response.url)
        if content_type_match not in response.headers["content-type"]:
            if hadoop_reporting:
                logger.info("Content type is not of correct type %s",
                            response.url)
            return False
    return True

def _is_correct_content_length(response, max_parse_size, hadoop_reporting):
    """ Verify the length of the content is suitable.

    response            requests.Response object.
    max_parse_size      Maximum length of content in characters.
    hadoop_reporting    Turn on hadoop reporting if True.
    """
    if "content-length" in response.headers:
        if hadoop_reporting:
            logger.info("Content length is %s: %s",
                        response.headers["content-length"], response.url)
        if int(response.headers["content-length"]) > max_parse_size:
            if hadoop_reporting:
                logger.info("Content length is %s NOT parsing: %s",
                            response.headers["content-length"], response.url)
            return False
    else:
        logger.info("Target %s does not have a content-length header, getting "
                    "size manually for ", response.url)
        size = sys.getsizeof(response.content)
        if size > max_parse_size:
            if hadoop_reporting:
                logger.info("Response is of size %d for url %s",
                            size, response.url)
            return False
    return True

if __name__ == "__main__":
 
    r = requests.get("http://www.ada.gov/hospcombrprt.pdf")
    print(parse_worthy(r))



