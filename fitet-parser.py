import requests as r
from bs4 import BeautifulSoup
import re

class Player:
    def __init__(self, name):
        self.name = name
        # print(f"Created player {name}")

players: dict[str, Player] = {}
def get_player(name):
    if name in players:
        return players[name]
    else:
        players[name] = Player(name)
        return players[name]    

class Match:
    def __init__(self, one, two, score: list[tuple[int, int]]):
        self.one: Player = one
        self.two: Player = two
        self.score: list[tuple[int, int]] = score
        # print(f"Created match {one.name} vs {two.name} with score {score}")

    def __str__(self):
        return f"{self.one.name} vs {self.two.name} with score {self.score}"


url = "https://portale.fitet.org/"

def parse_url(url):
    params = url.split("?")[-1].split("&")
    return {param.split("=")[0] : param.split("=")[1] for param in params}

def get_regioni():
    menu = r.get(url + "menu.php").text
    soup = BeautifulSoup(menu, "html.parser")
    tables = soup.find_all("table")
    cambionati = tables[1]
    manifestazioni = tables[3]
    classifiche = tables[5]
    regioni = tables[7]
    regioni = regioni.find_all("a")
    return {rg.text : parse_url(rg["href"]) for rg in regioni} # "REG"

def get_campionati(region_id):
    menu = r.get(url + "risultati/regioni/menu_reg.php", params={"REG": region_id}).text
    soup = BeautifulSoup(menu, "html.parser")
    campionati = soup.find_all("a")
    return {cmp.text : parse_url(cmp["href"]) for cmp in campionati} # "CAM"

def get_tornei_types(region_id):
    menu = r.get(url + "risultati/regioni/menu_tor.php", params={"REG": region_id}).text
    soup = BeautifulSoup(menu, "html.parser")
    tornei = soup.find_all("a")
    return {trn.text : parse_url(trn["href"]) for trn in tornei} # "TOR"

def get_tornei(tornei_id, region_id):
    tornei = r.get(url + "risultati/tornei/elenco_tornei.php", params={"TOR": tornei_id, "COMIT": region_id, "ID": 0}).text
    soup = BeautifulSoup(tornei, "html.parser")
    tornei = soup.find_all("a")
    return {trn.text : parse_url(trn["href"]) for trn in tornei} # "IDT" "TIPO"

def get_tabelloni(torneo_id, region_id):
    tabellone = r.get(url + f"risultati/tornei/tabelloni/{torneo_id}_{region_id}_home.html")
    if tabellone.status_code == 404:
        return None

    tabellone = tabellone.text
    soup = BeautifulSoup(tabellone, "html.parser")
    tabellone = soup.find_all("a")
    return {tbl.text : tbl["href"] for tbl in tabellone}


def get_tabellone(name, path):
    if "gironi" in name:
        return get_tabellone_gironi(path)
    elif "eliminatoria" in name:
        return get_tabellone_eliminatorie(path)
    else:
        print("Unknown tabellone type", name)


def get_tabellone_gironi(path):
    tab = r.get(url + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    # get all tr withoud bgcolor
    trs = soup.find_all("tr", {"bgcolor": None})
    out = [match_from_girone_row(tr) for tr in trs]
    return filter(None, out)


def match_from_girone_row(row):
    tds = row.find_all("td")
    if tds[0].text.isdigit():
        return None

    one = tds[0].text.strip()
    one = get_player(one)
    two = tds[1].text.strip()
    two = get_player(two)
    score = tds[3].text.strip().split(", ")
    if "assente" in score[0]:
        if "1" in score[0]:
            score = [(0, 11), (0, 11), (0, 11)]
        else:
            score = [(11, 0), (11, 0), (11, 0)]
    else:
        score = [(int(s.split("-")[0]), int(s.split("-")[1])) for s in score]
    return Match(one, two, score)


def get_tabellone_eliminatorie(path):
    tab = r.get(url + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    tr = soup.find_all("tr")
    return parse_eliminatorie_table(tr)


def parse_eliminatorie_table(rows):
    number = len(rows)
    assert number.bit_count() == 1 # is power of 2
    branches = [[x.text for x in row.find_all("font")] for row in rows]
    out = []
    # from log2(number) to 0
    for turn in range(number.bit_length()-1):
        for match_index in range(0, number, 2**(turn+1)):
            cell_one = branches[match_index][turn]
            cell_two = branches[match_index+ 2**turn][turn]
            if cell_two == "< X >" or cell_one == "< X >":
                continue
            result_cell = branches[match_index][turn+1]
            out.append(make_match_eliminatorie(cell_one, cell_two, result_cell))
    return out


def make_match_eliminatorie(cell_one, cell_two, result_cell):
    one = parse_eliminatorie_cell(cell_one)[0]
    two = parse_eliminatorie_cell(cell_two)[0]
    one = get_player(one)
    two = get_player(two)
    winner, score = parse_eliminatorie_cell(result_cell)
    winner = get_player(winner)
    other = two if winner == one else one
    return Match(winner, other, score)


def parse_eliminatorie_cell(text):
    spl = re.split(r"\([0-9]+\)", text, 1)
    return (spl[0].strip(), parse_eliminatorie_score(spl[1].strip()))


def parse_eliminatorie_score(score):
    sets = [int(x) for x in filter(None, score.split(","))]
    # reverse the tuple if the score is negative
    return [(max(11,abs(x)+2), abs(x))[::(1 if x >= 0 else -1)] for x in sets]

def get_tornei_matches(reg):
    out = []
    tornei_types = get_tornei_types(reg)
    all_tornei = {}
    for tipo in tornei_types.values():
        tornei = get_tornei(tipo["TOR"], reg)
        all_tornei.update(tornei)

    for torneo in all_tornei.values():
        tabelloni = get_tabelloni(torneo["IDT"], reg)
        if tabelloni is None:
            continue
        for name, path in tabelloni.items():
            out += get_tabellone(name, path)
    return out

def main():
    all_matches = []
    for name, attrs in get_regioni().items():
        if name != "Trentino":
            continue

        campionati = get_campionati(attrs["REG"])
        all_matches += get_tornei_matches(attrs["REG"])


    for match in all_matches: print(match)

if __name__ == "__main__":
    main()