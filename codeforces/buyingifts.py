def solve(l: list[tuple[int,int]]):

    # prendo il massimo a che è minore di b
    # prendo il massimo b che è minore di a

    aa = -1
    bb = -1
    for i in range(len(l)):
        if l[i][0]<l[i][1]:
            if aa == -1 or l[i][0]>l[aa][0]:
                aa = i

        if l[i][1]<l[i][0]:
            if bb == -1 or l[i][1]>l[bb][1]:
                bb = i

    if aa == -1 or bb == -1:
        cond = aa == -1
    else:
        cond = l[aa][0] > l[bb][1]
    
    if cond:
        # tutte le a sono maggiori di tutte le b
        # cerco la a più vicina a bb
        min_diff = 10**9
        for i in range(len(l)):
            if i == bb:
                continue

            if abs(l[i][0] - l[bb][1]) < min_diff:
                min_diff = abs(l[i][0] - l[bb][1])
                aa = i
        return min_diff

    else:
        # tutte le b sono maggiori di tutte le a
        # cerco la b più vicina a aa
        min_diff = 10**9
        for i in range(len(l)):
            if i == aa:
                continue

            if abs(l[i][1] - l[aa][0]) < min_diff:
                min_diff = abs(l[i][1] - l[aa][0])
                bb = i
        return min_diff

        



n_cases = int(input())
for _ in range(n_cases):
    n = int(input())
    l = []
    for _ in range(n):
        a, b = map(int, input().split())
        l.append((a, b))
    print(solve(l))