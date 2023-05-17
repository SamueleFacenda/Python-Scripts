from gmpy2 import mpz, iroot
from tqdm import tqdm, trange
import random
import math

N= 11854178668350132536998770600021775412418919136267711466659575504833480429106340292308672916005731985811172925720279068992464220293573546887342858910065901
e= 65537
d= 2454147980105506786425977989549345389561620074780357800626167210119179432413932079707729534686888191626633148799840568097408265451820012752747703117155329


e2= 5
ct= 11221865015245352586827949926936479339872912906868036678060873700351121339721754353868819679643501748382626251386036804928304376365191637409698833040968724
rnd = random.randint(1, 1e9)
assert rnd == pow(pow(rnd, e, N), d, N)


# find phi

prod = mpz(e) * mpz(d)
# d * e = phi * k + 1, k is an integer, smaller than e

for i in range(1, e):
    if prod % i == 1:
        phi = prod // i
        print(f"phi = {phi}")
        break

d2 = pow(e2, -1, phi)
print(f"d2 = {d2}")
pt = pow(ct, d2, N)
print(f"pt = {pt}")
print(int(pt).to_bytes((pt.bit_length() + 7) // 8, 'big'))