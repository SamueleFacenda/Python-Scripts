from base64 import b64decode
from threading import Thread, Lock
from dns import resolver
from tqdm import tqdm
import requests as req
import pickle
import re

visited = set()
reg = '( |\/)[a-zA-Z0-9_-]+\.challs\.olicyber\.it'

url = 'https://training.olicyber.it/api/'
psw = 'REDACTED=='
psw = b64decode(psw).decode() + ';'
email = 'samuele.facenda@gmail.com'
token = req.post(url + 'login', json={'email': email, 'password': psw}).json()['token']
print('logged')

#get all challenges indexes
events = req.get(url + 'challenges', headers={'Authorization': 'Token ' + token}).json()['events']
id = []
for event in events:
    for section in event['sections']:
        for challenge in section['challenges']:
            id.append(challenge['id'])
print('challenges id fetched')

alls = []
for i in tqdm(id):
    desc = req.get(url + 'challenges/' + str(i), headers={'Authorization': 'Token ' + token}).json()['description']
    # find all urls(*.challs.olicyber.it)
    matc = re.search(reg, desc)
    if matc:
        alls.append(matc.group(0)[1:])

print(alls)
with open('urls', 'wb') as f:
    pickle.dump(alls, f)


# parallel dns resolution for all urls
destinations = set()
mutex = Lock()

def resolve(domain):
    global mutex
    answers = resolver.resolve(domain, 'A')
    for ans in answers:
        mutex.acquire()
        destinations.add(ans.address)
        mutex.release()

threads = [Thread(target=resolve, args=[domain]) for domain in alls]
for t in threads:
    t.start()
for t in threads:
    t.join()

# interessante, me la sono menata tanto e c'è un solo server(sono due orette che scripto, le regex non funzionano, una settimana che non dormo)

print(destinations)
with(open('ipOlicyber', 'wb')) as f:
    pickle.dump(destinations, f)

