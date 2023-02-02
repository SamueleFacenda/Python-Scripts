import requests as r

print(r.head(
    'http://web-07.challs.olicyber.it',
).headers)