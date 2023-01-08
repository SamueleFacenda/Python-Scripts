import pokebase as pb
from tqdm import tqdm

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

# legge un file, riscrive tutto e (dovrebbe essere un csv pokemon) ritorna il numero del'ultimo pokemon aggiunto
def re_write(file):
    max_i = 0
    out=""
    for line in file:
        if max_i == 0:
            continue
        out += line + "\n"
        max_i = int(line.split(",")[0])
    file.write(out)
    return max_i


with open("pokedex.csv","w") as f:
    f.write("#,Name,Type 1,Type 2,Total,HP,Attack,Defense,Sp. Atk,Sp. Def,Speed,Generation,Legendary\n")
    for i in tqdm(range(1,1009)):
        # print(i)
        try:
            tmp= pb.pokemon(i)
            tmp_spec = pb.pokemon_species(i)
        except:
            print(i)
            break
        # print(tmp.name.title())
        # print([x.stat.name + "  " + str( x.base_stat) for x in tmp.stats])
        f.write(",".join(
        [
            str(i),
            tmp.name.title(),
            tmp.types[0].type.name,
            tmp.types[1].type.name if len(tmp.types) != 1 else "",
            str(150), # todo122,130,69,80,69,30,8,False,
            #880,Dracozolt,electric,dragon,150,90,100,90,80,70,75,8,False,
            #881,Arctozolt,electric,ice,150,90,100,90,90,80,55,8,False,
            #882,Dracovish,water,dragon,150,90,90,100,70,80,75,8,False,
            #883,Arctovish,water,ice,150,90,90,100,80,90,55,8,False,
            #884,Duraludon,steel,dragon,150,70,95,115,120,50,85,8,False,
            #885,Dreepy,dragon,ghost,150,28,60,30,40,30,82,8,False,
            #886,Drakloak,dragon,ghost,150,68,80,50,60,50,102,8,False,
            #887,Dragapult,dragon,ghost,150,88,120,75,100,75,142,8,False,
            #888,Zacian,fairy,,150,92,130,115,80,115,138,8,True,
            #889,Zamazenta,fighting,,150,92,130,115,80,115,138,8,True,
            #890,Eternatus,poison,dragon,150,140,85,95,145,95,130,8,True,
            #891,Kubfu,fighting,,150,60,90,60,53,50,72,8,True,
            #892,Urshifu-Single-Strike,fighting,dark,150,100,130,100,63,60,97,8,True,
            #893,Zarude,dark,grass,150,105,120,105,70,95,105,8,False,
            #894,Regieleki,electric,,150,80,100,50,100,50,200,8,True,
            #895,Regidrago,dragon,,150,200,100,50,100,50,80,8,True,
            #896,Glastrier,ice,,150,100,145,130,65,110,30,8,True,
            #897,Spectrier,ghost,,150,100,65,60,145,80,130,8,True,
            #898,Calyrex,psychic,grass,150,100,80,80,80,80,80,8,True,
            #899,Wyrdeer,normal,psychic,150,103,105,72,105,75,65,8,False,
            #900,Kleavor,bug,rock,150,70,135,95,45,70,85,8,False,
            #901,Ursaluna,ground,normal,150,130,140,105,45,80,50,8,False,
            #902,Basculegion-Male,water,ghost,150,120,112,65,80,75,78,8,False,
            #903,Sneasler,fighting,poison,150,80,130,60,40,80,120,8,False,
            #904,Overqwil,dark,poison,150,85,115,95,65,65,85,8,False,
            #905,Enamorus-Incarnate,fairy,flying,150,74,115,70,135,80,106,8,True,
            
        ] +
        [str(x.base_stat) for x in tmp.stats] + 
        [
            str(romanToDecimal(tmp_spec.generation.name.split("-")[1].upper())),
            str(tmp_spec.is_legendary),
            "\n"
        ]
        ))


