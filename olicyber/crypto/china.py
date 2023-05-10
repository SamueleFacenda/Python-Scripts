from math import gcd

def is_coprime(a, b):
    return gcd(a, b) == 1

def phi(x):
    if x == 1:
        return 1
    amount = 0
    for k in range(1, x):
        if is_coprime(x, k):
            amount += 1
    return amount

def china(a, n):
    N = 1
    for i in n:
        N *= i
    y = [N//i for i in n]
    z = [pow(y[i], phi(n[i])-1, n[i]) for i in range(len(n))]
    x = 0
    for i in range(len(n)):
        x += a[i]*y[i]*z[i]
    return x%N, N

a = [3,27,0,11,7]
n = [6,29,37,41,95]

print(china(a, n))