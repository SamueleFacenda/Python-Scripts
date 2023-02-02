from hashlib import md5
from collections import deque

# search a string beginning with 0e and some hex digists with md5 with same property
digits = '123456789'
bfs = deque()
bfs.append('0e')
while True:
    current = bfs.popleft()
    for i in digits:
        tmp = current + i
        hash = md5(tmp.encode()).hexdigest()[0:24]
        if hash.startswith('0e') and hash[2:].isdigit():
            print(tmp, hash)
            exit()
        else:
            bfs.append(tmp)