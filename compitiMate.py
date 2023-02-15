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
                comb.add(tuple(sorted((i, j))))
    d = 0
    for i in comb:
        d += prod(i) * prod([1-x for x in l if x not in i])
    print(f'{d:.5f}')

provaA()