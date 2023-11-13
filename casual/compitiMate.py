from functools import lru_cache

def prod(l):
    p = 1
    for i in l:
        p *= i
    return p

def provaA():
    l = (.6, .7, .5, .9, .8)

    a = 0
    for i in l:
        tmp = [1-x for x in l if x != i]
        a += prod(tmp) * i
    print(f'{a:.5f}')

    b = prod(l)
    print(f'{b:.5f}')

    c = prod([1-x for x in l])
    print(f'{c:.5f}')

    comb = set()
    for i in l:
        for j in l:
            if i != j:
                comb.add(tuple(sorted([i, j])))
    d = 0
    for i in comb:
        d += prod(i) * prod([1-x for x in l if x not in i])
    print(f'{d:.5f}')

@lru_cache
def fact(n):
    if n == 0:
        return 1
    return n * fact(n-1)

@lru_cache
def comb(n, k):
    return fact(n) // (fact(k) * fact(n-k))

@lru_cache
def probVenganoN(n, tot=22, p=5/6):
    return (1-p) ** (tot-n) * (p) ** n * comb(tot, n)

def simulazioneOverbooking(posti, book, prob, precision=100):
    import random
    over = 0
    for _ in range(precision):
        n = 0
        for __ in range(book):
            if random.random() < prob:
                n += 1
        if n > posti:
            over += 1
    return over / precision


def esercizioOverbooking():
    posti = 17
    booked = 22
    prob_venire = 5/6
    prob = sum(probVenganoN(n, booked, prob_venire) for n in range(posti+1, booked+1))
    print(f'{prob:.5f}')
    print(simulazioneOverbooking(posti, booked, prob_venire, 10000))

esercizioOverbooking()
