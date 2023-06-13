from pwn import *
from time import perf_counter as time, sleep
from tqdm import trange, tqdm
context.log_level = 'error'


# nc time.challs.olicyber.it 10505
def get_process():
    p = remote('time.challs.olicyber.it', 10505)
    p.recvuntil(b'> ')
    return p

p = get_process()

flag_len = 25 * 8
starting = b'flag{'
starting = bin(int.from_bytes(starting, 'big'))[2:].zfill(len(starting) * 8)

known = 'flag{Ou_\xee_\xed3r0_1_3_Sa1v4}'
wanded_bytes = [range(flag_len)] + [8, 10]
wanted_bits = []

def get_time_for_bit(bit):
    p.sendline(b'1')
    p.recvuntil(b'ricevere? ')
    p.clean()
    p.sendline(str(bit).encode())
    start = time()
    while not p.can_recv():
        pass
    end = time()
    p.recvuntil(b'> ')
    return end - start

avg_n = 5
flag = [0] * flag_len


for _ in trange(avg_n, position=0):
    for i in trange(flag_len, position=1, leave=False):
        try:
            flag[i] += get_time_for_bit(i)
        except:
            p.close()
            p = get_process()
            flag[i] += get_time_for_bit(i)


print(flag)
zero = []
one = []

for bit, taim in zip(starting, flag):
    if bit == '0':
        zero.append(taim)
    else:
        one.append(taim)

zero = sum(zero) / len(zero)
one = sum(one) / len(one)

print(zero, one)
treshold = (zero + one) / 2

flag = [1 if bit > treshold else 0 for bit in flag]
flag = ''.join([str(bit) for bit in flag])
print(flag)
flag = [int(flag[i:i+8], 2) for i in range(0, len(flag), 8)]
print(flag)
flag = bytes(flag)
print(flag)