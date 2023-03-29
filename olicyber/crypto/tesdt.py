bytess = [0 for _ in range(8)]

n = 234


for i in range(256):
    he = n&i

    # save in bytess the bit setted at one
    for j, c in enumerate(bin(he)[2:].zfill(8)):
        if c == '1':
            bytess[j] += 1
print(bytess)

# where bytess is 128, the bit is setted
# where bytess is 0, the bit is not setted
# assemble the binary string
bi = ''
for i in range(8):
    if bytess[i] == 128:
        bi += '1'
    else:
        bi += '0'

print(bi)

# print n in binary
print(bin(n)[2:])