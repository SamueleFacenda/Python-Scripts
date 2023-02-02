import requests as r

print(r.options(
    'http://web-10.challs.olicyber.it/'
).headers)

print(r.patch(
    'http://web-10.challs.olicyber.it/'
).headers)