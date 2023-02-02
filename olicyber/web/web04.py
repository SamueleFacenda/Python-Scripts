import requests as r

print(r.get(
    'http://web-04.challs.olicyber.it/users',
    headers={'Accept': 'application/xml'}
    ).text)