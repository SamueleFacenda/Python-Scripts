from pwn import *

p = remote('nt-master.challs.olicyber.it', 11001)

for _ in range(10):
    p.recvuntil(b'N = ')

    n = int(p.recvuntil(b'\n', drop=True).strip())

    # gcd = 1

    b = 1
    a = n - 1

    p.sendline(str(a) + ' ' + str(b))

p.interactive()