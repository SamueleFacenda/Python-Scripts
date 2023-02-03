from pwn import *

# ci mette una decina di tentativi ma poi va

#p = process('./challenge.py')
p = remote('cryptorland.challs.olicyber.it', 10801)

nums = []
for _ in range(10):
    nums.append(int(p.recvline().strip()))
bins = [bin(n)[2:] for n in nums]
useAnd = []
for b in bins:
    num_of_ones = b.count("1")
    useAnd.append(num_of_ones < len(b) / 2)
print(useAnd)

max_len = max([len(x) for x in bins])
for i in range(len(bins)):
    bins[i] = bins[i].zfill(max_len)

secret = []
n_and = sum(useAnd)
n_or = len(useAnd) - n_and
for col in range(max_len):
    one_and = len([x for use_and, x in zip(useAnd, bins) if x[col] == "1" and use_and])
    zero_and = n_and - one_and
    one_or = len([x for use_and, x in zip(useAnd, bins) if x[col] == "1" and not use_and])
    zero_or = n_or - one_or

    one = one_and + one_or
    zero = zero_and + zero_or

    secret.append("1" if one > zero else "0")

integer = int("".join(secret), 2)
print(integer)
p.sendline(str(integer).encode())
print(p.recvline())



    

