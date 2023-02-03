#!/usr/bin/env python3

import os
import random
import signal

TIMEOUT = 300

flag = 'flag{y0u_c4n_4nd_0r_n0t}' 

def handle():
    secret = int.from_bytes(os.urandom(12), byteorder = 'big')

    for _ in range(10):
        
        rnd = int.from_bytes(os.urandom(12), byteorder = 'big')
        
        if random.randint(0, 1) == 0:
            print(secret & rnd)
        else:
            print(secret | rnd)
            
    guess = int(input('Qual è la chiave segreta? '))
    
    if guess == secret:
        print('Congratulazioni! Ecco a te la flag:', flag)
    else:
        print('Nope!')

if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
