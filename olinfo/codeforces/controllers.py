
n = int(input())
string = input()
assert len(string) == n

q = int(input())

def check(A, B) -> bool:
    if A == B:
        return P == M

    K = B * (P-M) / (A-B)
    if int(K) != K:
        # non è un intero
        return False
    return -P <= K <= M

P = string.count('+')
M = string.count('-')

for _ in range(q):
    a, b = tuple(map(int, input().split()))
    print('YES' if check(a, b) else 'NO')