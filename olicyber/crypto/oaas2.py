from pwn import *
from tqdm import trange


p = remote("otp2.challs.olicyber.it", 12306)

p.recvuntil(b'connessione\n')

n_try = 5001

def get_line_to_list():
    l = p.recvline().decode()
    l = l.split("-")
    return [int(x) for x in l]


pkt = b'e\n' * n_try
p.send(pkt)
log.info("sent data")

mins = get_line_to_list()


for _ in trange(n_try-1):
    tmp = get_line_to_list()
    mins = [min(a,b) for (a,b) in zip(tmp, mins)]
p.sendline(b'q')

print(''.join([chr(x) for x in mins]))