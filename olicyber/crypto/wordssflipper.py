from pwn import *
from base64 import b64decode, b64encode

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

p = remote('flip.challs.olicyber.it', 10603)

msg = b"Dammi la flaaag!"

p.sendline(b'1')
p.sendline(msg)
p.recvuntil(b'richiesta: ')
enc = p.recvline().strip()

p.recvuntil(b'IV: ')
iv = p.recvline().strip().decode()
iv = b64decode(iv)

saved = b'{"admin": false, "msg": "Dammi la flaaag!"}'
saved = saved[:16]

wanted = b'{"admin": true, "msg": "Dammi la flaaag!"}'
wanted = wanted[:16]

iv = xor(xor(iv, saved), wanted)

p.sendline(b'2')
p.sendline(enc)
p.sendline(b64encode(iv))

p.recvuntil(b'qui: ')
flag = p.recvline().strip().decode()
p.close()
print(flag)
