import requests as r
from multiprocessing.pool import ThreadPool
from collections import deque
from time import time, sleep
from threading import Lock

TLD_LIST = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
DOMAIN_CHECK = 'https://api.godaddy.com/v1/domains/available?domain={}&checkType=FULL&forTransfer=false'

HEADERS = {
    'accept': 'application/json',
    'Authorization': f'sso-key {GODADDY_API_KEY}:{GODADDY_SECRET}',
}

AVAILABLE_FILE = 'available.txt'
file_lock = Lock()

def get_tld_list():
    response = r.get(TLD_LIST)
    return response.text.splitlines()[1:]

query_times = deque()
lock = Lock()

def api_delay():
    # max 60 requests per minute
    while True:
        with lock:
            while len(query_times) and query_times[0] < time() - 60:
                query_times.popleft()
            if len(query_times) < 60:
                query_times.append(time())
                print(len(query_times))
                return
        sleep(0.5)

def is_domain_available(domain):
    api_delay()
    response = r.get(DOMAIN_CHECK.format(domain), headers=HEADERS)
    json = response.json()
    print(response.text)
    if 'code' in json and json['code'] == 'UNSUPPORTED_TLD':
        return False
    if 'code' in json:
        print(json['message'])
    return json['available']

formats = [
    # '{protocol}://{domain}',
    # '{protocol}://{domain}.',
    '{protocol}://www.{domain}',
]

protocols = ['http']
pool = ThreadPool(10)
available = set()

def has_www(tld):
    for protocol in protocols:
        for format in formats:
            domain = format.format(protocol=protocol, domain=tld)
            try:
                response = r.get(domain)
            except r.exceptions.ConnectionError:
                if is_domain_available('www.' + tld):
                    available.add(tld)
                    with file_lock:
                        with open(AVAILABLE_FILE, 'a') as f:
                            f.write(tld + '\n')
                    print(domain, 'is available!!!!!!!!!')
                else:
                    print(domain, 'is not available')
                continue
            if response.status_code == 200:
                pass#print(domain)
            
def main():
    # clear the file
    open(AVAILABLE_FILE, 'w').close()
    tlds = get_tld_list()
    pool.map(has_www, tlds)

if __name__ == '__main__':
    main()