from Crypto.Cipher import AES
from Crypto.Random.random import randint
from hashlib import sha256
from tqdm import trange, tqdm

def expand_pin(pin):
    return sha256(pin).digest()[:16]

token = '06c8580019a5422c13b0c57b7484c518'
token = bytes.fromhex(token)
    
passfrase = b"donttrustgabibbo"
pins = [str(i).zfill(6).encode() for i in range(1000000)]
pins = [(pin, expand_pin(pin)) for pin in pins]

crypted_passfrases = {}
for pin, expanded in tqdm(pins, leave=False):
    c2 = AES.new(expanded, AES.MODE_ECB)
    crypted_passfrases[c2.encrypt(passfrase)] = pin

for pin, expanded in tqdm(pins, leave=False):
    c1 = AES.new(expanded, AES.MODE_ECB)
    decr = c1.decrypt(token)
    if decr in crypted_passfrases:
        print("User pin: ", pin.decode())
        print("Server pin: ", crypted_passfrases[decr].decode())
        break
