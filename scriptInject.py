esa='0'#woo1
pos=0#woo2
dir='.'#woo3

import os
l = os.listdir(dir)
l.remove('output.txt')
l.remove('input.txt')
#l.remove('stderr.txt')
stringa = str(l)[1:-1].replace("'", "").replace(" ", "").replace(",", " ")
stringa = bytes(stringa, 'utf-8').hex() + '00'
if stringa[pos] == esa:
    exit(10)