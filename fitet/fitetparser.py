import requests as r
from bs4 import BeautifulSoup
import re
from functools import partial
from icecream import ic
import json
from datetime import datetime
from functools import lru_cache, partial

from .entities import Match, Player, ChampionshipMatch, Tournament, Persistency, TTEvent
from .threadutils import WaitableThreadPool
from .caching import cached

from sqlalchemy import inspect

class Error404(Exception): 
    pass

URL = "https://portale.fitet.org/"


### Urls fetchers ###

def make_soup_res(path, params={}, headers={}):
    req = r.get(URL + path, params=params, headers=headers)
    if req.status_code == 404:
        raise Error404()
    return BeautifulSoup(req.text, "html.parser")

def parse_url(url):
    params = url.split("?")[-1].split("&")
    return {param.split("=")[0] : param.split("=")[1] for param in params}

def fetch_homepage():
    soup = make_soup_res("menu.php")
    tables = soup.find_all("table")
    cambionati = tables[1]
    manifestazioni = tables[3]
    classifiche = tables[5]
    regioni = tables[7]
    return {
        "campionati" : cambionati,
        "manifestazioni" : manifestazioni,
        "classifiche" : classifiche,
        "regioni" : regioni
    }

@cached
def fetch_regioni():
    regioni = fetch_homepage()["regioni"]
    regioni = regioni.find_all("a")
    return {rg.text : parse_url(rg["href"]) for rg in regioni} # "REG"

def get_results_urls_parsed(path, params={}, parse=True):
    soup = make_soup_res("risultati/" + path, params)
    urls = soup.find_all("a")
    return {url.text : parse_url(url["href"]) if parse else url["href"] for url in urls}

@cached   
def fetch_campionati(region):
    return get_results_urls_parsed("regioni/menu_reg.php", {"REG": region}) # "CAM"

@cached
def fetch_tornei_types(region):
    return get_results_urls_parsed("regioni/menu_tor.php", {"REG": region}) # "TOR"

@cached
def fetch_tornei(tor_type, region):
    return get_results_urls_parsed("tornei/elenco_tornei.php", {"TOR": tor_type, "COMIT": region, "ID": 0}) # "IDT" "TIPO"

# do not cache this, it is uploaded after the tournament
def fetch_tabelloni(torneo, region):
    try:
        return get_results_urls_parsed(f"tornei/tabelloni/{torneo}_{region}_home.html", parse=False)
    except Error404:
        # not played yet
        return None

@cached
def fetch_anno_campionato(campionato):
    header = r.get(URL + "risultati/campionati/testa_campionati.php", params={"CAM": campionato}).text
    soup = BeautifulSoup(header, "html.parser")
    return parse_url(soup.find("a")["href"])["ANNO"]

# do not cache this, it is updated after a championship match is played
def fetch_giornate(campionato, anno):
    calendar = r.get(URL + "risultati/campionati/Calendario.asp", params={"CAM": campionato, "ANNO": anno}).text
    soup = BeautifulSoup(calendar, "html.parser")

    incontri = soup.find_all("a", string=lambda x: x.strip() != "-")[1:] # first is the STAMPA button

    return [parse_url(inc["href"]) for inc in incontri] # INCONTRO CAM FORMULA

# IMPORTANT: this is cached, but the cache is cleared every run
@lru_cache(maxsize=1)
def fetch_last_classifica():
    classifiche = fetch_homepage()["classifiche"]
    # must contain a date
    latest = classifiche.find("a", string=re.compile(r"\d{2}/\d{2}/\d{4}"))
    out = parse_url(latest["href"])
    out["date"] = datetime.strptime(latest.text, "%d/%m/%Y")
    return out# "ID_CLASS" "ID" "PASS" "date"

@cached
def fetch_player_id(name, classifica=211):
    name = name.lower().strip()
    res = r.get(URL + "risultati/new_rank/ajax.php", params={"term": name}, headers={"X-Requested-With": "XMLHttpRequest"})
    res = res.json()
    # some players are two times in the database
    ids = [x["id"] for x in res]
    id = filter(partial(validate_player_id, classifica=classifica), ids)
    try:
        return next(id)
    except StopIteration:
        raise ValueError(f"Player {name} not found in classifica {classifica}")

NO_ATLETA_STR = "Non sono presenti dettagli per questo atleta in questa classifica!"
@cached
def validate_player_id(id, classifica=211):
    #res = r.get(URL + "risultati/new_rank/dettaglioatleta_unica.php", params={"ATLETA": id, "ID_CLASS": classifica, "ZU": 1, "AVVERSARIO": 0}).text
    soup = make_soup_res("risultati/new_rank/dettaglioatleta_unica.php", params={"ATLETA": id, "ID_CLASS": classifica, "ZU": 1, "AVVERSARIO": 0}, headers={"X-Requested-With": "XMLHttpRequest"})
    # get body text
    res = soup.body.text
    return NO_ATLETA_STR != res.strip()

@cached
def fetch_player_score(id, classifica):
    soup = make_soup_res("risultati/new_rank/dettaglioatleta_unica.php", params={"ATLETA": id, "ID_CLASS": classifica, "ZU": 1, "AVVERSARIO": 0}, headers={"X-Requested-With": "XMLHttpRequest"})
    text = soup.find("p", class_="style_scheda2", string=re.compile("punti")).text
    points = re.search(r"\d+,\d+", text).group(0).replace(",", ".")
    return int(float(points))

## Match parsers ##

def make_player(name):
    classifica = fetch_last_classifica()["ID_CLASS"]
    if "-" in name or "/" in name:
        # double match player
        return Player(name)

    try:
        id = fetch_player_id(name, classifica)
        score = fetch_player_score(id, classifica)
    except ValueError:
        #player not in the classifica
        return Player(name)
    
    return Player(name, score)

def make_match_from_girone_row(row):
    tds = row.find_all("td")
    if tds[0].text.isdigit():
        return None

    one, two, sets, score = [td.text.strip() for td in tds]

    if one == '<?>' or two == '<?>':
        return None

    one = one.title().strip()
    two = two.title().strip()
    score = score.split(", ")

    if "assente" in score[0] or "ritirato" in score[0]:
        if "1" in score[0]:
            score = [(0, 11)] * 3
        else:
            score = [(11, 0)] * 3
    else:
        score = [(int(s.split("-")[0]), int(s.split("-")[1])) for s in score]

    return Match(make_player(one), make_player(two), score)

def make_match_eliminatorie(cell_one, cell_two, result_cell):
    one = parse_eliminatorie_cell(cell_one)[0].title().strip()
    two = parse_eliminatorie_cell(cell_two)[0].title().strip()

    winner, score = parse_eliminatorie_cell(result_cell)

    winner = winner.title().strip()

    other = two if winner == one else one
    return Match(make_player(winner), make_player(other), score)

def make_match_from_giornata_row(row):
    td = row.find_all("td")
    if not td[0].text.strip().isdigit():
        return None

    one = td[1].text.strip().title()
    two = td[2].text.strip().title()
    # for each set
    sets = []
    for i in range(5):
        points_one = td[3+i*2].text.strip()
        points_two = td[4+i*2].text.strip()
        if points_one == "0" and points_two == "0":
            break
        sets.append((int(points_one), int(points_two)))
    
    return Match(make_player(one), make_player(two), sets)


## Complex parsers ##

def parse_eliminatorie_table(rows):
    number = len(rows)
    branches = [[x.text for x in row.find_all("font")] for row in rows]
    out = [] # deque would be better, but the lenght is <100

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

def parse_eliminatorie_cell(text):
    spl = re.split(r"\([0-9]+\)", text)
    return (spl[0].strip(), parse_eliminatorie_score(spl[-1].strip()))

def parse_eliminatorie_score(score):
    # (R) means retired, the set score is 0
    sets = [int(x) if not "(R)" in x else 0 for x in filter(None, score.split(","))]

    # reverse the tuple if the score is negative
    return [(max(11,abs(x)+2), abs(x))[::(1 if x >= 0 else -1)] for x in sets]

## Container class for parsing ##

class FitetParser:

    def __init__(self, dump_path=None, verbose=False):
        self.matches_dump_path = dump_path

        self.persistency = Persistency(self.matches_dump_path, verbose=verbose)

        self._already_parsed_events_names = TTEvent.get_all_names(self.persistency)

        self.pool = WaitableThreadPool(10)

    @property
    def matches(self):
        return Match.get_all(self.persistency)

    def update(self, wanted_regions=None):
        self.add_all_new_matches(wanted_regions)

    def add_all_new_matches(self, wanted_regions=None):

        regs = fetch_regioni()
        regs = {k:v for k,v in regs.items() if (not wanted_regions or k in wanted_regions)}
        regs = [x["REG"] for x in regs.values()]

        tornei_types = fetch_tornei_types(regs[0])
        tornei_types = [tt["TOR"] for tt in tornei_types.values()]

        self.pool.map_async(self.add_campionati_matches, regs)
        self.pool.starmap_async(self.add_tornei_matches, list(zip(regs, [tornei_types] * len(regs))))

        # wait for all threads to finish, then make sure no strange thigs modify the output
        self.pool.wait_and_end()

    def add_matches_from_giornata(self, incontro, campionato):
        event = ChampionshipMatch(campionato, incontro)
        if event.name in self._already_parsed_events_names:
            return
        self._already_parsed_events_names.add(event.name)

        soup = make_soup_res("risultati/campionati/giornata.php", params={"CAM": campionato, "INCONTRO": incontro, "FORMULA": 1})

        date = soup.find("b", string=re.compile("Giornata")).text
        date = re.search(r"\d{2}/\d{2}/\d{4}", date).group(0)
        event.date = datetime.strptime(date, "%d/%m/%Y")

        # get the second div in body direct children of body
        div = soup.body.find_all("div", recursive=False)[1]
        rows = div.find_all("tr")
        out = list(filter(None, [make_match_from_giornata_row(row) for row in rows]))
        for match in out: match.event = event
        
        Match.persist_all(self.persistency, out)

    def add_campionato_matches(self, campionato, anno):
        incontri  = fetch_giornate(campionato, anno)
        self.pool.starmap_async(self.add_matches_from_giornata, [(i["INCONTRO"], i["CAM"]) for i in incontri])

    def add_campionati_matches(self, reg):
        campionati = fetch_campionati(reg)
        if not campionati:
            # Val D'Aosta :(
            return
        campionati = [x["CAM"] for x in campionati.values()]
        anno = fetch_anno_campionato(campionati[0])

        self.pool.map_async(partial(self.add_campionato_matches, anno=anno), campionati)

    def add_torneo_matches(self, name, id, reg):
        event = Tournament(id, reg)
        if event.name in self._already_parsed_events_names:
            return
        self._already_parsed_events_names.add(event.name)
        
        date = re.search(r"\d{2}/\d{2}/\d{4}", name).group(0)
        event.date = datetime.strptime(date, "%d/%m/%Y")

        tabelloni = fetch_tabelloni(id, reg)
        if tabelloni is None:
            # not played yet
            return

        # keys are names
        # values are paths
        self.pool.starmap_async(partial(self.add_tabellone, event=event), tabelloni.items())
    
    def add_tornei_matches(self, reg, types):
        tornei = self.pool.imap_unordered(partial(fetch_tornei, region=reg), types)

        for torneo_type_dict in tornei:
            names_ids = [(name, val["IDT"]) for name, val in torneo_type_dict.items()]
            self.pool.starmap_async(partial(self.add_torneo_matches, reg=reg), names_ids)

    def add_tabellone(self, name, path, event):
        if "gironi" in name:
            self.add_tabellone_gironi(path, event)
        elif "eliminatoria" in name:
            self.add_tabellone_eliminatorie(path, event)
        elif "Top AB" in name:
            pass # TODO schifo
        else:
            print("Unknown tabellone type", name)
            print("Path", path)

    def add_tabellone_eliminatorie(self, path, event):
        soup = make_soup_res("risultati/tornei/tabelloni/" + path)
        tr = soup.find_all("tr")
        if soup.find("i"):
            # i is intestation text for the two tables
            principale = parse_eliminatorie_table(tr[:len(tr)//2])
            consolazione = parse_eliminatorie_table(tr[len(tr)//2:])
            out = principale + consolazione
        else:
            out = parse_eliminatorie_table(tr)
        
        for match in out: match.event = event

        Match.persist_all(self.persistency, out)

    def add_tabellone_gironi(self, path, event):
        soup = make_soup_res("risultati/tornei/tabelloni/" + path)
        # get all tr withoud bgcolor
        trs = soup.find_all("tr", {"bgcolor": None})
        out = [make_match_from_girone_row(tr) for tr in trs]

        out = list(filter(None, out))
        for match in out: match.event = event

        Match.persist_all(self.persistency, out)
