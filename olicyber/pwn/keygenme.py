from pwn import *

p = remote('keygenme.challs.olicyber.it', 10017)
#p = process('keygenme')

txt = p.recvuntil('chiave.\n').decode()
userid = txt.split('User id:')[1].split('\n')[0].strip()
print("userid: ", userid)

def pairStrings(uno, due):
    i_uno = 0
    i_due = 0
    i_tre = 0
    out = ''

    while (i_due < 8 or i_tre < 8):
        if i_uno % 2 == 1:
            out += due[i_due]
            i_due += 1
        else:
            out += uno[i_tre]
            i_tre += 1
        i_uno += 1
    return out

def genKey(userid):
    key = ''
    key += pairStrings(userid[0x12:],userid[9:])
    key += pairStrings(userid,userid[0x12:])
    key += pairStrings(userid[9:],userid)
    return key

print(txt)
key = genKey(userid)
print("key: ", key)

p.sendline(key)
p.interactive()