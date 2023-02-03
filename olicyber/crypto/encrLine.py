
# read output.txt and convert from hex to bytes
with open('output.txt', 'r') as f:
    ciphertext = bytes.fromhex(f.read())


# [ i for i in range(255) if (ord('a') * i + 1) & 0xff == 0x26]
# così ho trovato che la chiave era 69

chars = []
for b in ciphertext:
    chars.append([i for i in range(255) if (69 * i + 1) & 0xff == b])

print(''.join([chr(i[0]) for i in chars]))