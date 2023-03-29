from pwn import *
from tqdm import trange

p = remote('segreto.challs-territoriale.olicyber.it', 33000)
#p = process('/mnt/c/Users/samue/Downloads/IndovinANDo.py')
for _ in range(10):
    ret = p.recvuntil(b'>', drop=True).strip()
    print(ret)

    bytess = [0 for _ in range(64)]

    for i in trange(256):
        p.sendline(str(i))
        he = p.recvuntil(b'>', drop=True).strip()
        he = bytes.fromhex(he.decode())

            # get the bit at position j
        strr = bin(int.from_bytes(he, 'big'))[2:].zfill(64)
        for j, c in enumerate(strr):
            if c == '1':
                bytess[j] += 1

    # where bytess is 128, the bit is setted
    # where bytess is 0, the bit is not setted
    # assemble the binary string
    bi = ''
    for i in range(64):
        if bytess[i] == 128:
            bi += '1'
        else:
            bi += '0'

    # convert the binary string to hex
    he = hex(int(bi, 2))[2:]
    print(he)

    p.sendline(b'g')
    p.sendline(he)


p.interactive()