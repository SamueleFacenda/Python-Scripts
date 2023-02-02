import requests as r

s = r.Session()
s.get('http://web-06.challs.olicyber.it/token')
# print cookies
print(s.cookies)
print(s.get(
    'http://web-06.challs.olicyber.it/flag'
).text)