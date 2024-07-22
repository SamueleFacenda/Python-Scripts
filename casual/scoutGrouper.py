import requests as req # pip install requests

# made with temp mail
API_KEY = 'eGqpICzZPZ2myX8TwG49a6JSyMO6LLQ6pgU0aYu1'

URL = 'https://api.quantumnumbers.anu.edu.au?length=1024&type=uint16'

tende = [3] * 5 + [2] * 4

params = {"length": 1024, "type": "uint8", "size": 1}
headers = {"x-api-key": API_KEY}

def download_random_numbers():
    response = req.get(URL, headers=headers, params=params).json()
    if not response['success']:
        raise Exception('Failed to get random numbers ' + response['message'])
    return response['data']

randoms = []
def get_random_numbers(n):
    global randoms
    if len(randoms) < n:
        randoms += download_random_numbers()
    res = randoms[:n]
    randoms = randoms[n:]
    return res

class Scout :
    def __init__(self, nome, anno, mf, iscapo):
        self.nome = nome.strip()
        self.anno = int(anno)
        self.sex = mf.strip()
        self.iscapo = iscapo.strip() == '1'
    
    def __repr__(self):
        return f"{self.nome}"
    
def parse_scouts(filename):
    with open(filename, 'r') as f:
        scouts = f.read()
    scouts = scouts.strip().split('\n')
    scouts.pop(0)
    scouts = [scout.split(',') for scout in scouts]
    scouts = [Scout(*scout) for scout in scouts]
    return scouts

def partition_by_type(scouts):
    return {
        'capo': partition_by_sex([x for x in scouts if x.iscapo]),
        'noncapo': partition_by_sex([x for x in scouts if not x.iscapo])
    }

def partition_by_sex(scouts):
    return { # non molto inclusivo
        'maschi': [x for x in scouts if x.sex == 'm'],
        'femmine': [x for x in scouts if x.sex == 'f']
    }

scouts = parse_scouts('casual/scouts.csv')
scouts = partition_by_type(scouts)

def removed(l, x):
    l = l.copy()
    l.remove(x)
    return l

def make_tende(n_scouts, tents):
    if n_scouts <= 0:
        return []
    if not tents:
        return None
    if n_scouts in tents:
        return [n_scouts]
    poss = {t:make_tende(n_scouts - t, removed(tents, t)) for t in set(tents)}
    poss = {k:v for k,v in poss.items() if v is not None}
    if not poss:
        return None
    best_fit = list(poss.keys())[0]
    for k,v in poss.items():
        if k + sum(v) < best_fit + sum(poss[best_fit]):
            best_fit = k
    return [best_fit] + poss[best_fit]

def make_tende_for_group(group):
    if type(group) == list:
        tents = make_tende(len(group), tende)
        for t in tents:
            tende.remove(t)
        return tents
    return {k:make_tende_for_group(v) for k,v in group.items()}

def flatten_set(tende, prefix=''):
    if type(tende) == list:
        return {prefix:tende}
    out = {}
    for k,v in tende.items():
        out.update(flatten_set(v, prefix + ('-' if prefix else '') + k))
    return out

def adjust_tende(scouts, tende):
    offsets = {k:sum(tende[k]) - len(scouts[k]) for k in tende.keys()}
    mins = list(offsets.keys())[:1]
    maxs = list(offsets.keys())[:1]
    for k, offset in list(offsets.items())[1:]:
        if offset == offsets[mins[0]]:
            mins.append(k)
        if offset == offsets[maxs[0]]:
            maxs.append(k)
        if offset < offsets[mins[0]]:
            mins = [k]
        if offset > offsets[maxs[0]]:
            maxs = [k]

    if offsets[maxs[0]] - offsets[mins[0]] <= 1:
        return tende
    
    # pick the biggest min and the smallest max and swap a tent
    min_key = mins[0]
    for k in mins:
        if len(tende[k]) > len(tende[min_key]):
            min_key = k
    max_key = maxs[0]
    for k in maxs:
        if len(tende[k]) < len(tende[max_key]):
            max_key = k
    best_couple = (tende[min_key][0], tende[max_key][0])
    for tmin in tende[min_key]:
        for tmax in tende[max_key]:
            if tmin >= tmax:
                continue
            if tmax - tmin > offsets[max_key]:
                continue
            if tmax - tmin - offsets[min_key]//2 < best_couple[1] - best_couple[0]:
                best_couple = (tmin, tmax)

    if best_couple[0] >= best_couple[1]:
        return tende

    tende[min_key].remove(best_couple[0])
    tende[max_key].append(best_couple[0])
    tende[max_key].remove(best_couple[1])
    tende[min_key].append(best_couple[1])
    return adjust_tende(scouts, tende)

def fit_tende(tende, scouts):
    for k in tende.keys():
        # print(f"Using {sum(tende[k])} places for {len(scouts[k])} scouts")
        # dumb method
        offset = sum(tende[k]) - len(scouts[k])
        if not offset:
            continue
        biggest_tent = max(tende[k])
        tende[k].remove(biggest_tent)
        tende[k].append(biggest_tent - offset)
        print(f"A {biggest_tent} people tent will be used by {biggest_tent - offset} {k}")
    return tende

tende = make_tende_for_group(scouts)
tende = flatten_set(tende)
scouts = flatten_set(scouts)
tende = adjust_tende(scouts, tende)
tende = fit_tende(tende, scouts)

banned_couples = [
    ('simo', 'samu'),
    ('lisa', 'silvia')
]

# a list of scouts is valid if they are not all of two consecutive years
def validate_tenda(tenda):
    names = [scout.nome for scout in tenda]
    for a,b in banned_couples:
        if a in names and b in names:
            return False

    if all([scout.iscapo for scout in tenda]):
        return True
    anni = list(set([scout.anno for scout in tenda]))
    if len(anni) == 1:
        return False
    if len(anni) == 2:
        return abs(anni[0] - anni[1]) != 1
    return True


# fisher-yates shuffle    
def shuffle(l):
    randoms = get_random_numbers(len(l)-1)
    for i in range(len(l) - 1):
        j = randoms.pop() % (len(l) - i) + i
        l[i], l[j] = l[j], l[i]
    return l

def assign_tende_for_group(scouts, tende):
    while True:
        out = []
        shuffled = shuffle(scouts)
        for t in tende:
            out.append(shuffled[:t])
            shuffled = shuffled[t:]
        if all([validate_tenda(t) for t in out]):
            break
    return out
    
def assign_tende(scouts, tende):
    for k,v in scouts.items():
        print(f"Assigning tende for {k}")
        groups = assign_tende_for_group(v, tende[k])
        print(groups)

assign_tende(scouts, tende)
