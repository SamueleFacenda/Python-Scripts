#!/usr/bin/python3

def main():
    p = input('n')
    q = input('q')
    p = int(p)
    q = int(q)
    n = p * q
    print(f'{n=}')
    m = float('inf')
    while m >= n:
        m = int(input('m'))
        print(f'{m=}')
    fi = (p-1) * (q-1)
    print(f'{fi=}')
    e = int(input('e'))
    print(f'{e=}')    
    c = pow(m, e, n)
    print(f'{c=}')
    
if __name__ == '__main__':
    main()
