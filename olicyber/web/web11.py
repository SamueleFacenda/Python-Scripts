import requests as r

s = r.Session()
csrf = s.post(
    'http://web-11.challs.olicyber.it/login',
    json={'username': 'admin', 'password': 'admin'},
).json()['csrf']
flag = ''
for i in range(4):
    re = s.get(
        'http://web-11.challs.olicyber.it/flag_piece',
        params={'index': i, 'csrf': csrf}
    ).json()
    csrf = re['csrf']
    flag += re['flag_piece']

print(flag)