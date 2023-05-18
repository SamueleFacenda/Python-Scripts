import requests as req
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
import json

url = 'http://packet.challs.olicyber.it/message'

s = req.Session()

msg = s.post(url, json = {}).text
msg = json.loads(msg)
data = msg['message']
data = data.split('\n')
p = data[0].split(' ')[-1]
g = data[1].split(' ')[-1]
A = data[2].split(' ')[-1]

p = int(p, 16)
g = int(g, 16)
A = int(A, 16)


my_prime = getPrime(1024)
my_public = pow(g, my_prime, p)

msg = s.post(url, json = msg).text
msg = s.post(url, json = {'message': 'B: ' + hex(my_public)[2:], 'from': 'Bob'}).text

k = pow(A, my_prime, p)

msg = json.loads(msg)
data = msg['message']
data = data.split('\n')
enc = data[0].split(' ')[-1]
iv = data[1].split(' ')[-1]

enc = bytes.fromhex(enc)
iv = bytes.fromhex(iv)

aes = AES.new(k.to_bytes(32, 'big'), AES.MODE_CBC, iv)
flag = aes.decrypt(enc)
print(flag)