""" Rotate between proxies in a list """

import random

def get_random_proxy(proxy_list):
    """ ... guess ... 
    Get a random proxy from the list provided.
    proxy_list  entries formatted as {<scheme>: <URI or IP>}.
    """
    return random.choice(proxy_list)

if __name__ == "__main__":

    print get_random_proxy([{"http" : "127.0.0.1"}, {"http" : "127.0.0.2"}])
