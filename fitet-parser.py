import requests as r
from bs4 import BeautifulSoup
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from collections import deque


class Player:
    def __init__(self, name):
        self.name: str = name
        self.matches: deque["Match"] = deque()
        # print(f"Created player {name}")

    instances: dict[str, "Player"] = {}
    def get(name) -> "Player":
        name = name.strip().title()
        if name in Player.instances:
            return Player.instances[name]
        else:
            Player.instances[name] = Player(name)
            return Player.instances[name]    

class Match:
    def __init__(self, one, two, score: list[tuple[int, int]], date=None):
        self.one: Player = one
        self.two: Player = two
        self.score: list[tuple[int, int]] = score
        self.date = date
        
        self.one.matches.append(self)
        self.two.matches.append(self)
        Match.instances.append(self)

    instances: deque["Match"] = deque()

    def __str__(self):
        return f"{self.date}: {self.one.name} vs {self.two.name} with score {self.score}"


URL = "https://portale.fitet.org/"

def parse_url(url):
    params = url.split("?")[-1].split("&")
    return {param.split("=")[0] : param.split("=")[1] for param in params}

def get_regioni():
    menu = r.get(URL + "menu.php").text
    soup = BeautifulSoup(menu, "html.parser")
    tables = soup.find_all("table")
    cambionati = tables[1]
    manifestazioni = tables[3]
    classifiche = tables[5]
    regioni = tables[7]
    regioni = regioni.find_all("a")
    return {rg.text : parse_url(rg["href"]) for rg in regioni} # "REG"

def get_campionati(region_id):
    menu = r.get(URL + "risultati/regioni/menu_reg.php", params={"REG": region_id}).text
    soup = BeautifulSoup(menu, "html.parser")
    campionati = soup.find_all("a")
    return {cmp.text : parse_url(cmp["href"]) for cmp in campionati} # "CAM"

def get_tornei_types(region_id):
    menu = r.get(URL + "risultati/regioni/menu_tor.php", params={"REG": region_id}).text
    soup = BeautifulSoup(menu, "html.parser")
    tornei = soup.find_all("a")
    return {trn.text : parse_url(trn["href"]) for trn in tornei} # "TOR"

def get_tornei(tornei_id, region_id):
    tornei = r.get(URL + "risultati/tornei/elenco_tornei.php", params={"TOR": tornei_id, "COMIT": region_id, "ID": 0}).text
    soup = BeautifulSoup(tornei, "html.parser")
    tornei = soup.find_all("a")
    return {trn.text : parse_url(trn["href"]) for trn in tornei} # "IDT" "TIPO"

def get_tabelloni(torneo_id, region_id):
    tabellone = r.get(URL + f"risultati/tornei/tabelloni/{torneo_id}_{region_id}_home.html")
    if tabellone.status_code == 404:
        # not played yet
        return None

    tabellone = tabellone.text
    soup = BeautifulSoup(tabellone, "html.parser")
    tabellone = soup.find_all("a")
    return {tbl.text : tbl["href"] for tbl in tabellone}


def get_tabellone(name, path, date):
    if "gironi" in name:
        get_tabellone_gironi(path, date)
    elif "eliminatoria" in name:
        get_tabellone_eliminatorie(path, date)
    elif "Top AB" in name:
        rpass # TODO schifo
    else:
        print("Unknown tabellone type", name)
        print("Path", path)


def get_tabellone_gironi(path, date):
    tab = r.get(URL + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    # get all tr withoud bgcolor
    trs = soup.find_all("tr", {"bgcolor": None})
    out = [match_from_girone_row(tr) for tr in trs]

    out = list(filter(None, out))
    for match in out: match.date = date

    with all_matches_lock:
        all_matches += out


def match_from_girone_row(row):
    tds = row.find_all("td")
    if tds[0].text.isdigit():
        return None

    one = tds[0].text.strip()
    one = Player.get(one)
    two = tds[1].text.strip()
    two = Player.get(two)
    score = tds[3].text.strip().split(", ")
    if "assente" in score[0] or "ritirato" in score[0]:
        if "1" in score[0]:
            score = [(0, 11)] * 3
        else:
            score = [(11, 0)] * 3
    else:
        score = [(int(s.split("-")[0]), int(s.split("-")[1])) for s in score]

    return Match(one, two, score)


def get_tabellone_eliminatorie(path, date):
    tab = r.get(URL + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    tr = soup.find_all("tr")
    if soup.find("i"):
        # i is intestation text for the two tables
        principale = parse_eliminatorie_table(tr[:len(tr)//2])
        consolazione = parse_eliminatorie_table(tr[len(tr)//2:])
        out = principale + consolazione
    else:
        out = parse_eliminatorie_table(tr)
    
    for match in out: match.date = date
    with all_matches_lock:
        all_matches += out


def parse_eliminatorie_table(rows):
    # round to lower log2
    number = len(rows)
    third_fourth = number.bit_count() != 1
    branches = [[x.text for x in row.find_all("font")] for row in rows]
    out = deque()

    if number.bit_count() != 1 and number:
        # third fourth place match
        cell_one = branches[-2][-2]
 
        cell_two = branches[-1][-1]
        result_cell = branches[-2][-1]

        if "-" not in result_cell:
            out.append(make_match_eliminatorie(cell_one, cell_two, result_cell))

        branches = branches[:-2]
        number -= 2

    # from 0 to log2(number)
    for turn in range(number.bit_length()-1):
        for match_index in range(0, number, 2**(turn+1)):
            cell_one = branches[match_index][turn]
            cell_two = branches[match_index+ 2**turn][turn]
            result_cell = branches[match_index][turn+1]

            # < X > or < X >- for skipped matches
            # - for not played matches
            if "< X >" in cell_one or "< X >" in cell_two or "-" in result_cell:
                continue

            out.append(make_match_eliminatorie(cell_one, cell_two, result_cell))

    return out


def make_match_eliminatorie(cell_one, cell_two, result_cell):
    one = parse_eliminatorie_cell(cell_one)[0]
    two = parse_eliminatorie_cell(cell_two)[0]

    one = Player.get(one)
    two = Player.get(two)
    winner, score = parse_eliminatorie_cell(result_cell)

    winner = Player.get(winner)
    other = two if winner == one else one
    return Match(winner, other, score)


def parse_eliminatorie_cell(text):
    spl = re.split(r"\([0-9]+\)", text)
    return (spl[0].strip(), parse_eliminatorie_score(spl[-1].strip()))


def parse_eliminatorie_score(score):
    # (R) means retired, the set score is 0
    sets = [int(x) if not "(R)" in x else 0 for x in filter(None, score.split(","))]

    # reverse the tuple if the score is negative
    return [(max(11,abs(x)+2), abs(x))[::(1 if x >= 0 else -1)] for x in sets]


def get_tornei_matches(reg):
    out = []
    tornei_types = get_tornei_types(reg)

    tornei = pool.map(partial(get_tornei, region_id=reg), tornei_types.values())
    all_tornei = {}
    for torneo_type_dict in as_completed(tornei):
        all_tornei.update(torneo_type_dict)

    ids = [x["IDT"] for x in all_tornei.values()]
    pool.map(partial(get_torneo_matches, reg=reg), all_tornei.keys(), ids)

def get_torneo_matches(name, id, reg):
    date = re.search(r"\d{2}/\d{2}/\d{4}", name).group(0)
    tabelloni = get_tabelloni(id, reg)
    if tabelloni is None:
        # not played yet
        return

    # keys are names
    # values are paths
    pool.map(partial(get_tabellone, path=reg, date=date), tabelloni.keys(), tabelloni.values())

def get_campionati_matches(reg):
    campionati = get_campionati(reg)
    campionati = [campionati["CAM"] for campionati in campionati.values()]
    anno = get_anno_campionato(campionati[0])

    pool.map(partial(get_girone_matches, anno=anno), campionati)


def get_anno_campionato(campionato):
    header = r.get(URL + "risultati/campionati/testa_campionati.php", params={"CAM": campionato}).text
    soup = BeautifulSoup(header, "html.parser")
    return parse_url(soup.find("a")["href"])["ANNO"]


def get_girone_matches(campionato, anno):
    incontri = get_giornate_list(campionato, anno)
    pool.map(get_matches_from_giornata, [i["INCONTRO"] for i in incontri], [i["CAM"] for i in incontri])


def get_giornate_list(campionato, anno):
    calendar = r.get(URL + "risultati/campionati/Calendario.asp", params={"CAM": campionato, "ANNO": anno}).text
    soup = BeautifulSoup(calendar, "html.parser")
    # get all a tag not containing only " - "
    incontri = soup.find_all("a", string=lambda x: x != " - ")[1:] # first is the STAMPA button
    return [parse_url(inc["href"]) for inc in incontri] # INCONTRO CAM FORMULA


def get_matches_from_giornata(giornata, campionato):
    risultato = r.get(URL + "risultati/campionati/giornata.php", params={"CAM": campionato, "INCONTRO": giornata, "FORMULA": 1}).text
    soup = BeautifulSoup(risultato, "html.parser")

    date = soup.find("b", string=re.compile("Giornata")).text
    date = re.search(r"\d{2}/\d{2}/\d{4}", date).group(0)

    # get the second div in body direct children of body
    div = soup.body.find_all("div", recursive=False)[1]
    rows = div.find_all("tr")
    out = list(filter(None, [parse_giornata_row(row) for row in rows]))
    for match in out: match.date = date
    
    with all_matches_lock:
        all_matches += out


def parse_giornata_row(row):
    td = row.find_all("td")
    if not td[0].text.strip().isdigit():
        return None

    one = td[1].text.strip()
    two = td[2].text.strip()
    # for each set
    sets = []
    for i in range(5):
        points_one = td[3+i*2].text.strip()
        points_two = td[4+i*2].text.strip()
        if points_one == "0" and points_two == "0":
            break

        sets.append((int(points_one), int(points_two)))
    return Match(Player.get(one), Player.get(two), sets)


def main():
    pool = ThreadPoolExecutor(max_workers=30)

    all_matches = deque()
    all_matches_lock = Lock()

    regs = get_regioni()
    # regs = {k:v for k,v in regs.items() if k == "Trentino"}
    regs = [x["REG"] for x in regs.values()]

    pool.map(get_campionati_matches, regs)
    pool.map(get_tornei_matches, regs)

    # wait for all threads to finish
    pool.shutdown(wait=True, cancel_futures=False)

    # for match in all_matches: print(match)
    print(len(all_matches))

    for match in Player.get("Facenda Samuele").matches: print(match)

if __name__ == "__main__":
    main()