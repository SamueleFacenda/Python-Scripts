import requests as r
from bs4 import BeautifulSoup
import re
from threading import Thread, Lock
from functools import partial

class Player:
    def __init__(self, name):
        self.name = name
        # print(f"Created player {name}")

players: dict[str, Player] = {}
def get_player(name):
    name = name.strip().title()
    if name in players:
        return players[name]
    else:
        players[name] = Player(name)
        return players[name]    

class Match:
    def __init__(self, one, two, score: list[tuple[int, int]], date=None):
        self.one: Player = one
        self.two: Player = two
        self.score: list[tuple[int, int]] = score
        self.date = date
        # print(f"Created match {one.name} vs {two.name} with score {score}")

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


def get_tabellone(name, path):
    if "gironi" in name:
        return get_tabellone_gironi(path)
    elif "eliminatoria" in name:
        return get_tabellone_eliminatorie(path)
    elif "Top AB" in name:
        return [] # TODO schifo
    else:
        print("Unknown tabellone type", name)
        print("Path", path)


def get_tabellone_gironi(path):
    tab = r.get(URL + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    # get all tr withoud bgcolor
    trs = soup.find_all("tr", {"bgcolor": None})
    out = [match_from_girone_row(tr) for tr in trs]
    return list(filter(None, out))


def match_from_girone_row(row):
    tds = row.find_all("td")
    if tds[0].text.isdigit():
        return None

    one = tds[0].text.strip()
    one = get_player(one)
    two = tds[1].text.strip()
    two = get_player(two)
    score = tds[3].text.strip().split(", ")
    if "assente" in score[0] or "ritirato" in score[0]:
        if "1" in score[0]:
            score = [(0, 11)] * 3
        else:
            score = [(11, 0)] * 3
    else:
        score = [(int(s.split("-")[0]), int(s.split("-")[1])) for s in score]

    return Match(one, two, score)


def get_tabellone_eliminatorie(path):
    tab = r.get(URL + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    tr = soup.find_all("tr")
    if soup.find("i"):
        # i is intastation text for the two tables
        principale = parse_eliminatorie_table(tr[:len(tr)//2])
        consolazione = parse_eliminatorie_table(tr[len(tr)//2:])
        return principale + consolazione
    else:
        return parse_eliminatorie_table(tr)


def parse_eliminatorie_table(rows):
    # round to lower log2
    number = len(rows)
    third_fourth = number.bit_count() != 1
    branches = [[x.text for x in row.find_all("font")] for row in rows]
    out = []

    if number.bit_count() != 1:
        # third fourth place match
        cell_one = branches[-2][-2]
        cell_two = branches[-1][-1]
        result_cell = branches[-2][-1]
        out.append(make_match_eliminatorie(cell_one, cell_two, result_cell))
        branches = branches[:-2]
        number -= 2

    # from 0 to log2(number)
    for turn in range(number.bit_length()-1):
        for match_index in range(0, number, 2**(turn+1)):
            cell_one = branches[match_index][turn]
            cell_two = branches[match_index+ 2**turn][turn]
            if "< X >" in cell_one or "< X >" in cell_two:
                continue
            try:
                result_cell = branches[match_index][turn+1]
            except IndexError:
                print("Error parsing cell", cell_one)
                print("Cells", cell_one, cell_two, result_cell)
                exit(1)
            out.append(make_match_eliminatorie(cell_one, cell_two, result_cell))

    return out


def make_match_eliminatorie(cell_one, cell_two, result_cell):
    try:
        one = parse_eliminatorie_cell(cell_one)[0]
        two = parse_eliminatorie_cell(cell_two)[0]
    except IndexError:
        print("Error parsing cell", cell_one)
        print("Cells", cell_one, cell_two, result_cell)
        exit(1)
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

    for name, torneo in all_tornei.items():
        date = re.search(r"\d{2}/\d{2}/\d{4}", name).group(0)
        tabelloni = get_tabelloni(torneo["IDT"], reg)
        if tabelloni is None:
            # not played yet
            continue

        for name, path in tabelloni.items():
            tmp = get_tabellone(name, path)
            for match in tmp:
                match.date = date
            out += tmp
    return out

def get_campionati_matches(reg):
    campionati = get_campionati(reg)
    out = []
    out_lock = Lock()
    threads = []
    for campionato in campionati.values():
        func = partial(get_campionati_matches_threaded, campionato["CAM"], out, out_lock)
        threads.append(Thread(target=func))
        threads[-1].start()

    for thread in threads: thread.join()
    return out

def get_campionati_matches_threaded(cmp, out, out_lock):
    anno = get_anno_campionato(cmp)
    tmp = get_girone_matches(cmp, anno)
    with out_lock:
        out += tmp


def get_anno_campionato(campionato):
    header = r.get(URL + "risultati/campionati/testa_campionati.php", params={"CAM": campionato}).text
    soup = BeautifulSoup(header, "html.parser")
    return parse_url(soup.find("a")["href"])["ANNO"]


def get_girone_matches(campionato, anno):
    incontri = get_giornate_list(campionato, anno)
    out = []
    for incontro in incontri:
        out += get_matches_from_giornata(incontro["INCONTRO"], incontro["CAM"])
    return out


def get_giornate_list(campionato, anno):
    calendar = r.get(URL + "risultati/campionati/Calendario.asp", params={"CAM": campionato, "ANNO": anno}).text
    soup = BeautifulSoup(calendar, "html.parser")
    # get all a tag not containing only " - "
    incontri = soup.find_all("a", string=lambda x: x != " - ")[1:] # first is the STAMPA button
    return [parse_url(inc["href"]) for inc in incontri] # INCONTRO CAM FORMULA


def get_matches_from_giornata(giornata, campionato):
    risultato = r.get(URL + "risultati/campionati/giornata.php", params={"CAM": campionato, "INCONTRO": giornata, "FORMULA": 1}).text
    soup = BeautifulSoup(risultato, "html.parser")
    try:
        date = soup.find("b", string=re.compile("Giornata")).text
        date = re.search(r"\d{2}/\d{2}/\d{4}", date).group(0)
    except TypeError as e:
        print("Error parsing giornata", giornata, "campionato", campionato)
        # print(soup)
        # print the stacktrace
        raise e
        exit(1)

    # get the second div in body direct children of body
    div = soup.body.find_all("div", recursive=False)[1]
    rows = div.find_all("tr")
    out = list(filter(None, [parse_giornata_row(row) for row in rows]))
    for match in out: match.date = date
    return out

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
    return Match(get_player(one), get_player(two), sets)

def main():
    all_matches = []
    for name, attrs in get_regioni().items():
        if name != "Trentino":
            pass
        
        # all_matches += get_campionati_matches(attrs["REG"])
        all_matches += get_tornei_matches(attrs["REG"])


    for match in all_matches: print(match)

if __name__ == "__main__":
    main()