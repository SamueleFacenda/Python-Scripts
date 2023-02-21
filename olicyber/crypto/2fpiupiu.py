from Crypto.Cipher import AES
from Crypto.Random.random import randint
from hashlib import sha256
from tqdm import trange, tqdm
from pwn import *

HOST = '2fapp.challs.olicyber.it' 
PORT = 12207

maxPin = 1000000

def expand_pin(pin):
    return sha256(pin).digest()[:16]

pins = [str(i).zfill(6).encode() for i in range(1, maxPin)]
aes = [(AES.new(expand_pin(pin), AES.MODE_ECB), pin) for pin in tqdm(pins, desc='Generating AES')]

zero = b'A'*16

toSend = []
table = {}

# https://crypto.stackexchange.com/questions/42362/how-can-i-attack-a-triple-block-cipher-with-2-keys-like-3des-with-a-cost-of-%E2%89%A4

for ae, i in tqdm(aes, desc='Decrypting'):
    m2 = ae.decrypt(zero)
    table[m2.hex()] = i
    toSend.append('3\nadmin\n' + m2.hex() + '\n')

toSend = ''.join(toSend)
print('len(kB):', len(toSend)//1024)


p = remote(HOST, PORT)
# mando tutto insieme, così e' piu' veloce
p.send(toSend.encode())
print('mandato payload')

uno = ''
due = ''
for ae, i in tqdm(aes, desc='Checking'):
    p.recvuntil(b'DEBUG token calcolato: ')
    token = p.recvline().decode().strip()
    # decrypt and get S^-1_K2(0)
    token = bytes.fromhex(token)
    m2 = ae.decrypt(token).hex()
    if m2 in table:
        print('Found:', table[m2], i)
        uno = i
        due = table[m2]
        break

payload = b'2\nadmin\n' + uno + b'\n' + due + b'\n'
p.send(payload)
# faccio arrivare tutto le risposte schifo del server, che non mi servono piu'
p.recvuntil(b'personale:', timeout=180)
p.recvuntil(b'admin')
flag = p.recvuntil(b'}').decode().strip()
p.close()
print(flag)
