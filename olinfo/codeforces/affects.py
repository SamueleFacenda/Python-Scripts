MOD = 998244353

N = int(input())
arr = [int(x) for x in input().split()]
# !! python sort
indx = sorted([(i+1, n) for i,n in enumerate(arr)], key=lambda x: x[1])
arr = [None] + arr # array with starting index 1

tot = 0
goods = 0 # numero di celle valide trovate fino ad ora
wheight = [1 for _ in range(N+1)] # per ogni cella, il numero di sottomultipli minori di essa (generato mano a mano)
for pos,n in indx:

    # trovo l'indice del massimo valore tra i suoi multipli
    max_val_in_multiples = pos
    for i in range(pos,N+1,pos):
        if arr[i] > arr[max_val_in_multiples]:
            max_val_in_multiples = i
    
    # due casi: e' lui il massimo o no
    if max_val_in_multiples == pos:
        # e' il massimo
        if wheight[pos] == 1:
            # le permutazioni sono 2^(n-1) (i modi possibili per accendere le celle trovate valide fino ad ora)
            tot += 2**(goods) * n
        else:
            # le permutazioni sono il prodotto di due valori:
            # il primo e' il numero di modi in cui posso colorare delle celle che sicuramente colorano anche quella attuale
            # (faccio il "-1" perche' almeno una deve essere accesa, escludo il caso in cui sono tutte spente)
            # il secondo e' il numero di modi in cui posso colorare tutte le altre celle (non mi cambia se sono accese o spente,
            # possono anche essere tutte spente)
            tot += (2**wheight[pos] -1) * 2**goods * n
            
        # adesso ho piu' numeri che non mi interessano (possono essere accesi oppure no)    
        goods += wheight[pos]
        
    else:
        # aumento il peso del massimo del "gruppo", quando sara' il suo turno contera' questa cella come sua "equivalente"
        wheight[max_val_in_multiples] += 1
    
print(tot % MOD)
