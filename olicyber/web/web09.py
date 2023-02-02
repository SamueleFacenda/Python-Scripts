import requests as r

print(r.post(
    'http://web-09.challs.olicyber.it/login',
    json={'username': 'admin', 'password': 'admin'},

).text)