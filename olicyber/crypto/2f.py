from Crypto.Cipher import AES
from Crypto.Random.random import randint
from hashlib import sha256
from tqdm import trange, tqdm

def hash_psw(pin1, pin2, passphrase = b"donttrustgabibbo"):
    c1 = AES.new(expand_pin(pin1), AES.MODE_ECB)
    c2 = AES.new(expand_pin(pin2), AES.MODE_ECB)
    return c1.encrypt(c2.encrypt(passphrase)).hex()


def expand_pin(pin):
    return sha256(pin).digest()[:16]
# b7d550abd9dffc5675efbb7382afc896

token = '06c8580019a5422c13b0c57b7484c518'
token = bytes.fromhex(token)

def hash_psw_better(pin2, passphrase = b"donttrustgabibbo"):
    c2 = AES.new(expand_pin(pin2), AES.MODE_ECB)
    
passfrase = b"donttrustgabibbo"
pins = [str(i).zfill(6).encode() for i in range(1000000))]
pins = [(pin, expand_pin(pin)) for pin in pins]

crypted_passfrases = {}
for pin, expanded in tqdm(pins, leave=False):
    c2 = AES.new(expanded, AES.MODE_ECB)
    crypted_passfrases[c2.encrypt(passfrase)] = pin

for pin, expanded in tqdm(pins, leave=False):
    c1 = AES.new(expanded, AES.MODE_ECB)
    decr = c1.decrypt(token)
    if decr in crypted_passfrases:
        print(pin.decode())
        print(crypted_passfrases[decr].decode())
        break
