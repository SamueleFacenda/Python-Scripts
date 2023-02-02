import requests as r

print(r.get(
    'http://web-03.challs.olicyber.it/flag',
    headers={"X-Password": 'admin'}
    ).text)