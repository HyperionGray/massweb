import random

def get_random_proxy(proxy_list):

    return random.choice(proxy_list)

if __name__ == "__main__":

    print get_random_proxy([{"http" : "127.0.0.1"}, {"http" : "127.0.0.2"}])
