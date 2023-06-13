from pwn import *
from randcrack import RandCrack
from tqdm import tqdm, trange
from Crypto.Cipher import AES
# nc lazy-platform.challs.olicyber.it 16004
r = remote('lazy-platform.challs.olicyber.it', 16004)
rc = RandCrack()
# need 624 * 32 

bytes_per_cycle = 32 + 16
cycles = (624 * 4) / bytes_per_cycle
cycles = int(cycles)
for _ in trange(cycles):
    r.sendline(b'1')
    r.sendline(b'a')
    r.recvuntil(b'Key: ')
    key = r.recvline().strip()
    r.recvuntil(b'IV: ')
    iv = r.recvline().strip()

    key = bytes.fromhex(key.decode())
    iv = bytes.fromhex(iv.decode())

    key = int.from_bytes(key, 'little')
    iv = int.from_bytes(iv, 'little')

    for i in range(32 // 4):
        tmp = key >> (i * 32) & 0xffffffff
        rc.submit(tmp)
    for i in range(16 // 4):
        tmp = iv >> (i * 32) & 0xffffffff
        rc.submit(tmp)

r.sendline(b'3')
r.recvuntil(b'Ciphertext: ')
flag = r.recvline().strip()
flag = bytes.fromhex(flag.decode())
key = rc.predict_getrandbits(32 * 8).to_bytes(32, "little")
iv = rc.predict_getrandbits(16 * 8).to_bytes(16, "little")

flag = AES.new(key, AES.MODE_CBC, iv).decrypt(flag)
print(flag)