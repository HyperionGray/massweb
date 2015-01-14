
import requests
import codecs
import sys
from requests import Response
import logging
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger('response_analysis.parse_worthy')
logger.setLevel(logging.INFO)
sys.stdin = codecs.getreader('utf-8')(sys.stdin)
sys.stderr = codecs.getwriter('utf-8')(sys.stderr)

def parse_worthy(response, max_parse_size=5000000, content_type_match="text",
                 hadoop_reporting=False):
    if not isinstance(response, Response):
        logger.warn("Response is of type %s with content %s", type(response), response)
        raise Exception("Response must be of type requests.Response")
    if not "content-type" in response.headers:
        if hadoop_reporting:
            logger.info("No Content Type header, not parsing " + unicode(response.url))
        return False
    else:
        logger.info("Content type is of type %s: %s", response.headers["content-type"], response.url)
        if not content_type_match in response.headers["content-type"]:
            if hadoop_reporting:
                logger.info("Content type is not of correct type %s", response.url)
            return False
    if "content-length" in response.headers:
        if hadoop_reporting:
            logger.info("Content length is %s: %s", response.headers["content-length"], response.url)
        if int(response.headers["content-length"]) > max_parse_size:
            if hadoop_reporting:
                logger.info("Content length is %s NOT parsing: %s",
                            response.headers["content-length"], response.url)
            return False
    else:
        logger.info("Target %s does not have a content-length header, getting size manually for ", response.url)
        size = sys.getsizeof(response.content)
        if size > max_parse_size:
            if hadoop_reporting:
                logger.info("Response is of size %d for url %s",
                            size, response.url)
            return False
    return True

if __name__ == "__main__":
 
    r = requests.get("http://www.ada.gov/hospcombrprt.pdf")
    print parse_worthy(r)



