import random
import os
from secret import flag


def encrypt(data, m, q=1):
    # l'input può essere visto come un solo byte(o 7)
    res = []
    for x in data:
        enc = (m*x+q) & 0xff
        # l'ultimo bit del cyphertext è il not dell plaintext
        res.append(enc)
    return bytes(res)


def main():
    key = 2*random.randint(0, 1 << 128)+1
    # l'ultimo bit è uno
    ciphertext = encrypt(flag.encode(), key)
    print(ciphertext.hex())


main()
