import requests as r
from bs4 import BeautifulSoup
import re
from threading import Lock
from functools import partial
from collections import deque
from icecream import ic
from time import sleep
from fitet.threadutils import WaitableThreadPool

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

    def __str__(self):
        return f"{self.date}: {self.one.name} vs {self.two.name} with score {self.score}"


class Error404(Exception): pass

URL = "https://portale.fitet.org/"

def make_soup_res(path, params):
    req = r.get(URL + path, params=params)
    if req.status_code == 404:
        raise Error404()
    return BeautifulSoup(req.text, "html.parser")

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


def get_results_urls_parsed(path, params={}, parse=True):
    soup = make_soup_res("risultati/" + path, params)
    urls = soup.find_all("a")
    return {url.text : parse_url(url["href"]) if parse else url["href"] for url in urls}
    
def get_campionati(region):
    return get_results_urls_parsed("regioni/menu_reg.php", {"REG": region}) # "CAM"

def get_tornei_types(region):
    return get_results_urls_parsed("regioni/menu_tor.php", {"REG": region}) # "TOR"

def get_tornei(tor_type, region):
    return get_results_urls_parsed("tornei/elenco_tornei.php", {"TOR": tor_type, "COMIT": region, "ID": 0}) # "IDT" "TIPO"

def get_tabelloni(torneo, region):
    try:
        return get_results_urls_parsed(f"tornei/tabelloni/{torneo}_{region}_home.html", parse=False)
    except Error404:
        # not played yet
        return None


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

    global all_matches, all_matches_lock
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
    global all_matches, all_matches_lock
    with all_matches_lock:
        all_matches += out


def parse_eliminatorie_table(rows):
    number = len(rows)
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


def get_tornei_matches(reg, types):
    tornei = pool.imap_unordered(partial(get_tornei, region=reg), types)
    for torneo_type_dict in tornei:
        names_ids = [(name, val["IDT"]) for name, val in torneo_type_dict.items()]
        pool.starmap_async(partial(get_torneo_matches, reg=reg), names_ids)


def get_torneo_matches(name, id, reg):
    date = re.search(r"\d{2}/\d{2}/\d{4}", name).group(0)
    tabelloni = get_tabelloni(id, reg)
    if tabelloni is None:
        # not played yet
        return

    # keys are names
    # values are paths
    pool.starmap_async(partial(get_tabellone, date=date), tabelloni.items())

def get_campionati_matches(reg):
    campionati = get_campionati(reg)
    if not campionati:
        # Val D'Aosta :(
        return
    campionati = [x["CAM"] for x in campionati.values()]
    anno = get_anno_campionato(campionati[0])

    pool.map_async(partial(get_girone_matches, anno=anno), campionati)


def get_anno_campionato(campionato):
    header = r.get(URL + "risultati/campionati/testa_campionati.php", params={"CAM": campionato}).text
    soup = BeautifulSoup(header, "html.parser")
    return parse_url(soup.find("a")["href"])["ANNO"]


def get_girone_matches(campionato, anno):
    incontri = get_giornate_list(campionato, anno)
    pool.starmap_async(get_matches_from_giornata, [(i["INCONTRO"], i["CAM"]) for i in incontri])


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
    
    global all_matches, all_matches_lock
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
        try:
            sets.append((int(points_one), int(points_two)))
        except ValueError:
            ic(td)
            raise
    return Match(Player.get(one), Player.get(two), sets)


def get_all_matches(wanted_regions=None):
    global all_matches, all_matches_lock, pool

    pool = WaitableThreadPool(50)

    all_matches = deque()
    all_matches_lock = Lock()

    regs = get_regioni()
    regs = {k:v for k,v in regs.items() if k in wanted_regions}
    regs = [x["REG"] for x in regs.values()]

    tornei_types = get_tornei_types(regs[0])
    tornei_types = [tt["TOR"] for tt in tornei_types.values()]

    pool.map_async(get_campionati_matches, regs)
    pool.starmap_async(get_tornei_matches, list(zip(regs, [tornei_types] * len(regs))))

    # wait for all threads to finish, then make sure no strange thigs modify the output
    pool.wait_and_end()
    all_matches_lock.acquire()
    
    return all_matches

def main():

    matches = get_all_matches(["Trentino"])

    # for match in all_matches: print(match)
    print(len(matches))

    for match in Player.get("Facenda Samuele").matches: print(match)

if __name__ == "__main__":
    main()
