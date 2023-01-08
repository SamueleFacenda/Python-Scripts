from tqdm import trange, tqdm
import time

def gcd(p,q):
# Create the gcd of two positive integers.
    while q != 0:
        p, q = q, p%q
    return p
def is_coprime(x, y):
    return gcd(x, y) == 1


p = 13
q = 7

#p = 11
#q = 5

n = p * q

z = (p-1) * (q-1)

# gen all e

e_arr = []
for i in trange(2, z - 2):
    if is_coprime(i, z):
        e_arr.append(i)

# cerco una d nei primi tot numeri 

# max d
tot = 30

result = []

for e in tqdm(e_arr):
    for d in trange(1, tot):
        if (d * e ) % z == 1 :
            result.append((e, d))

print(f"number of results: {len(result)}")
time.sleep(2)


for e, i in result:
    print(f"d: {i}, e: {e}")


print(f"{p=}, {q=}, {n=}, {z=}")
print(f"best result,  e: {result[-1][0]}, d: {result[-1][1]}")
print(f" e*d: {result[-1][0] * result[-1][1]}, resto: (e*d)%z: {(result[-1][0] * result[-1][1])%z}")