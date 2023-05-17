from pwn import *
from base64 import b64decode

p = remote('bob.challs.olicyber.it', 10602)

flag = b''

block_size = 16

printable = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '

while True:
    msg = b'a' * (block_size - len('Bob: '))

    flag_send = flag
    if len(flag_send) >= block_size:
        flag_send = flag_send[-block_size + 1:]
        #print(flag_send)
        #print(len(flag_send))
    pad = block_size - len(flag_send) - 1
    for c in printable:
        msg += b'a' * pad + flag_send + bytes([c])

    if len(flag) < block_size:
        msg += b'a' * (pad)
    else:
        #print(len(flag) % block_size)
        msg += b'a' * (block_size - len(flag) % block_size - 1)

    #mssg = b'Bob: ' + msg
    #print([mssg[i:i+block_size] for i in range(0, len(mssg), block_size)])

    p.sendline(msg)
    p.sendline(b'1')

    p.recvuntil('messaggio!\n')
    enc = p.recvline().strip()
    enc = b64decode(enc)
    blocks = [enc[i:i+block_size] for i in range(0, len(enc), block_size)]
    blocks = blocks[1:]
    to_check = blocks[len(printable) + len(flag) // block_size]
    for i in range(len(printable)):
        if to_check == blocks[i]:
            flag += printable[i].to_bytes(1, 'big')
            print(flag)
            break
    else:
        p.close()
        print('TRANSMISSION ENDED! -------')
        flag = flag.decode()
        flag = flag.split('}')[0] + '}'
        flag = 'flag{' + flag.split('flag{')[1]
        print(flag)
        break
