import requests as r
from bs4 import BeautifulSoup

class Player:
    def __init__(self, name):
        self.name = name
        print(f"Created player {name}")

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
        print(f"Created match {one.name} vs {two.name} with score {score}")

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
    return {cmp.text : parse_url(cmp["href"]) for trn in tornei} # "TOR"

def get_tornei(tornei_id, region_id):
    tornei = r.get(url + "risultati/regioni/elenco_tornei.php", params={"TOR": tornei_id, "COM": region_id}).text
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
        get_tabellone_gironi(path)
    elif "eliminazione" in name:
        get_tabellone_eliminatorie(path)

def get_tabellone_gironi(path):
    tab = r.get(url + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    # get all tr withoud bgcolor
    trs = soup.find_all("tr", {"bgcolor": None})
    out = []
    for tr in trs:
        tds = tr.find_all("td")
        if isdigit(tds[0].text):
            continue
        one = tds[0].text.removeprefix("&nbsp;")
        one = get_player(one)
        two = tds[1].text.removeprefix("&nbsp;")
        two = get_player(two)
        score = tds[3].text.removeprefix("&nbsp;").split(", ")
        score = [(int(s.split("-")[0]), int(s.split("-")[1])) for s in score]
        out.append(Match(one, two, score))
        
def get_tabellone_eliminatorie(path):
    tab = r.get(url + "risultati/tornei/tabelloni/" + path).text
    soup = BeautifulSoup(tab, "html.parser")
    tr = soup.find_all("tr")
    number = len(tr)
    assert number.bit_count() == 1 # is power of 2

    return # TODO

for name, attrs in get_regioni():
    if name != "Trentino":
        continue
    campionati = get_campionati(attrs["REG"])
    tornei_types = get_tornei_types(attrs["REG"])
    all_tornei = []
    for tipo in tornei_types:
        tornei = get_tornei(tipo["TIPO"], attrs["REG"])
        all_tornei.extend(tornei)

    for torneo in all_tornei:
        tabelloni = get_tabelloni(torneo["IDT"], attrs["REG"])
        if tabelloni is None:
            continue
        for tabellone in tabelloni:
            get_tabellone(tabellone, tabelloni[tabellone])
