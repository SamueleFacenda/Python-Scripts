# import pokebase as pb
from tqdm import tqdm, trange
import os
import requests as req
from sys import argv
from multiprocessing.pool import ThreadPool

# conversion da numeri romani a decimali, brutal copy-paste

romanValue = {
    'i': 1,
    'ii': 2,
    'iii': 3,
    'iv': 4,
    'v': 5,
    'vi': 6,
    'vii': 7,
    'viii': 8,
    'ix': 9,
    'x': 10,
    'xi': 11,
    'xii': 12,
}


# legge un file e (dovrebbe essere un csv pokemon) ritorna il numero dell'indice massimo
def get_max_index(file):
    indexes = [int(line.split(",")[0]) for line in file if len(line.strip()) != 0 and not line.startswith("Name")]
    return max(indexes)

path = "pokedex.csv" if len(argv) == 1 else argv[1]
exist = os.path.isfile(path)

if exist:
    with open(path,"r") as f:
        max_i = get_max_index(f)
else:
    max_i = 0

def getPokemon(pokedex_number):
    try:
        url = "https://pokeapi.co/api/v2/pokemon-species/" + str(pokedex_number)
        specie_stats = req.get(url).json()
        url = "https://pokeapi.co/api/v2/pokemon/" + str(pokedex_number)
        pokemon_stats = req.get(url).json()
    except:
        print(pokedex_number)
        return None

    return {
        "id": str(pokedex_number),
        "name": pokemon_stats['name'].lower(),
        "type1": pokemon_stats['types'][0]['type']['name'],
        "type2": pokemon_stats['types'][1]['type']['name'] if len(pokemon_stats['types']) != 1 else "",
        "total": str(sum([x['base_stat'] for x in pokemon_stats['stats']])),
        "hp": str(pokemon_stats['stats'][0]['base_stat']),
        "attack": str(pokemon_stats['stats'][1]['base_stat']),
        "defense": str(pokemon_stats['stats'][2]['base_stat']),
        "sp_attack": str(pokemon_stats['stats'][3]['base_stat']),
        "sp_defense": str(pokemon_stats['stats'][4]['base_stat']),
        "speed": str(pokemon_stats['stats'][5]['base_stat']),
        "generation": str(romanValue[specie_stats['generation']['name'].split("-")[1]]),
        "legendary": str(specie_stats['is_legendary'])
    }

poke_count = req.get("https://pokeapi.co/api/v2/pokemon-species/").json()['count']

with open(path, "a" if exist else "w") as f:
    if not exist:
        f.write("Name,Type 1,Type 2,Total,HP,Attack,Defense,Sp. Atk,Sp. Def,Speed,Generation,Legendary\n")

    with ThreadPool(20) as pool:

        for i in tqdm(pool.imap(getPokemon, range(max_i+1,poke_count+1)), total=poke_count-max_i):
            f.write(",".join(i.values()) + "\n")

