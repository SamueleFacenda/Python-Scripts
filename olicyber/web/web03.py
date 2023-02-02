import requests as r

print(r.get(
    'http://web-02.challs.olicyber.it/server-records',
    params={"id": 'flag'}
    ).text)