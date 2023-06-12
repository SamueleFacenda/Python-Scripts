from Crypto.PublicKey import RSA
from math import gcd

with open('root.pem', 'r') as f:
    root = RSA.importKey(f.read())

with open('flag.txt.enc', 'rb') as f:
    enc = f.read()

# other kleys are in the keys directory

keys = []
for i in range(1, 50):
    with open('keys/key_%d.pem' % i, 'r') as f:
        keys.append(RSA.importKey(f.read()))



for k in keys:
    if gcd(k.n, root.n) != 1:
        p = gcd(k.n, root.n)
        q = root.n // p
        break

phi = (p - 1) * (q - 1)
d = pow(root.e, -1, phi)
flag = pow(int.from_bytes(enc, 'big'), d, root.n)
print(flag.to_bytes(1024, 'big'))