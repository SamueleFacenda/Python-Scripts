from pwn import *

enc = '866bb5802051d56f37b1073a501b4afe4324424336ba60d4efe9af817b27a95a0f3adec8b809088bbaaebbfa0629c079'
enc = bytes.fromhex(enc)

def get_conn():
    return remote('modes.challs.olicyber.it', 10802)

iv = enc[:16]
enc = enc[16:]
blocks = [enc[i:i+16] for i in range(0, len(enc), 16)]

last = iv

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])
out = b''

for block in blocks:
    p = get_conn()
    p.recvuntil('ciphertext: ')
    p.sendline(block.hex())
    decoded = bytes.fromhex(p.recvline().strip().decode())
    p.close()

    out += xor(last, decoded)
    last = block

print(out)