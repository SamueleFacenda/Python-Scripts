# import pokebase as pb
from tqdm import tqdm, trange
import os
import requests as req

# pip install pokebase, può dare problemi con versione python 3.10

# conversion da numeri romani a decimali, brutal copy-paste
def value(r):
    if (r == 'I'):
        return 1
    if (r == 'V'):
        return 5
    if (r == 'X'):
        return 10
    if (r == 'L'):
        return 50
    if (r == 'C'):
        return 100
    if (r == 'D'):
        return 500
    if (r == 'M'):
        return 1000
    return -1
 
def romanToDecimal(str):
    res = 0
    i = 0
    while (i < len(str)):
        s1 = value(str[i])
        if (i + 1 < len(str)):
            s2 = value(str[i + 1])
            if (s1 >= s2):
                res = res + s1
                i = i + 1
            else:
                res = res + s2 - s1
                i = i + 2
        else:
            res = res + s1
            i = i + 1
    return res

# legge un file e (dovrebbe essere un csv pokemon) ritorna il numero dell'ultimo pokemon aggiunto
def get_max_index(file):
    max_i = 0
    for line in file:
        if len(line.strip()) == 0 or line[0] == "#":
            continue
        max_i = int(line.split(",")[0])
    return max_i

path = "pokedex.csv"
exist = os.path.isfile(path)

if exist:
    with open(path,"r") as f:
        max_i = get_max_index(f)
else:
    max_i = 0


with open(path, "a" if exist else "w") as f:
    if not exist:
        f.write("Name,Type 1,Type 2,Total,HP,Attack,Defense,Sp. Atk,Sp. Def,Speed,Generation,Legendary\n")

    for i in trange(max_i+1,1009):
        try:
            # tmp= pb.pokemon(i)
            # tmp_spec = pb.pokemon_species(i)
            url = " https://pokeapi.co/api/v2/pokemon-species/" + str(i)
            tmp_spec = req.get(url).json()
            url = " https://pokeapi.co/api/v2/pokemon/" + str(i)
            tmp = req.get(url).json()
        except:
            print(i)
            break

        f.write(",".join(
            [
                str(i),
                tmp['name'],
                tmp['types'][0]['type']['name'],
                tmp['types'][1]['type']['name'] if len(tmp['types']) != 1 else "",
                str(sum([x['base_stat'] for x in tmp['stats']])),
            ] +
            [str(x['base_stat']) for x in tmp['stats']] + 
            [
                str(romanToDecimal(tmp_spec['generation']['name'].split("-")[1].upper())),
                str(tmp_spec['is_legendary']),
                "\n"
            ]
        ))
