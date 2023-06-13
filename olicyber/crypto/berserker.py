from pwn import *
from tqdm import trange, tqdm
from math import ceil

p = None
last_IV_for_flag = None

# user={name};flag={flag}
# 5 + len(name) + 6
block = 16
base_name_len = block - len('user=') - len(';flag=')
flag_len = 32
alphabet = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'

flag = b'flag{'


# nc berserker.challs.olicyber.it 10507
def get_process():
    p = remote('berserker.challs.olicyber.it', 10507)
    p.recvuntil(b'> ')
    return p

def get_cookie(name):
    p.sendline(b'1')
    p.sendline(name)
    p.recvuntil(b'cifrato: ')
    cookie = p.recvline().strip()

    return bytes.fromhex(cookie.decode())

def cipher(msg):
    p.sendline(b'2')
    p.sendline(msg)
    p.recvuntil(b'Messaggio cifrato: ')
    ciphertext = p.recvline().strip()

    return bytes.fromhex(ciphertext.decode())

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def get_new_letter():
    known_len = len(flag)
    name_len = base_name_len + (block - known_len % block) + block - 1
    name = b'a' * name_len
    expected_str = f'user={name.decode()};flag=' + flag.decode()
    to_check = expected_str[-block + 1:].encode()

    cookie = get_cookie(name)
    wanted_iv = cookie[len(expected_str) + 1 - block - block: len(expected_str) + 1 - block]
    ciphered_to_check = cookie[len(expected_str) + 1 - block: len(expected_str) + 1]

    latest_iv = cookie[-block:]
    for letter in tqdm(alphabet, position=1, leave=False, desc= flag.decode()):
        to_send = to_check + bytes([letter])
        to_send = xor(to_send, latest_iv)
        to_send = xor(to_send, wanted_iv)
        ciphered = cipher(to_send.hex().encode())
        if ciphered[:block] == ciphered_to_check:
            return letter
        
        latest_iv = ciphered[-block:]

    raise Exception('No letter found')

p = get_process()
for _ in trange(flag_len - len(flag), position=0):
    tmp = get_new_letter()
    flag += tmp.to_bytes(1, 'big')

print(flag)