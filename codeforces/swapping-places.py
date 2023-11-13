#!/usr/bin/env python3


# Input parsing

S, L, N = input().split()
S = int(S)
L = int(L)
N = int(N)

tmp = [input() for _ in range(S)]
tmp.sort()

species = {i: b for i,b in enumerate(tmp)}
nums = {b:a for a,b in species.items()}
friends = [[False] * S for _ in range(S)]

for _ in range(L):
    a, b = input().split()
    friends[nums[a]][nums[b]] = True
    friends[nums[b]][nums[a]] = True
    
l = [nums[a] for a in input().split()]



# Implementation

# Provo un bubble sort stupido

for i in range(N):
    for e in range(N-1):
    
        if l[e] > l[e+1] and friends[l[e]][l[e+1]]:
            l[e], l[e+1] = l[e+1], l[e]

out = l



# Print output
print(' '.join([species[a] for a in out]))
