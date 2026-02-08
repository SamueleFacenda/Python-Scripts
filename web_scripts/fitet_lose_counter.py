import requests
import bs4 as bs
from multiprocessing import Pool
from tqdm import tqdm

URL = "https://portale.fitet.org/risultati/new_rank/dettaglioatleta_unica.php?ATLETA={}&ID_CLASS=239&ZU=1&AVVERSARIO=0"
START_ID = 500_000
MAX_ID = 800_000

REDUCTION = 12000 / 16933

def get_points(id):
    r = requests.get(URL.format(id), headers={"X-Requested-With": "XMLHttpRequest"})
    if r.status_code != 200:
        return None
    soup = bs.BeautifulSoup(r.text, 'html.parser')
    total = soup.find('p', class_='dettagli')
    done = soup.find('p', class_='dettagli_r')
    if not total or not done:
        return None
    total = total.text.split(",")[0].strip().replace(".", "")
    done = done.text.split(",")[0].strip().replace(".", "")
    return int(total), int(done)

def main():
    with Pool(20) as pool:
        res = list(tqdm(pool.imap(get_points, range(START_ID, MAX_ID)), total=MAX_ID-START_ID))
    earning = 0
    losing = 0
    res = [r for r in res if r is not None]
    print(f"Got {len(res)} results out of {MAX_ID-START_ID} requests")
    for total, done in res:
        reduced = total * (1 - REDUCTION)
        if done > reduced:
            earning += 1
        else:
            losing += 1

    print(f"Earning: {earning}, Losing: {losing}")


if __name__ == "__main__":
    main()
