import requests
import requests.adapters
import bs4 as bs
from multiprocessing.pool import ThreadPool as Pool
from tqdm import tqdm

URL = "https://portale.fitet.org/risultati/new_rank/dettaglioatleta_unica.php?ATLETA={}&ID_CLASS=239&ZU=1&AVVERSARIO=0"
START_ID = 580_000
MAX_ID = 900_000

REDUCTION = 12000 / 16454 # bisi febryary 2026

CACHE_FILE = "dump.csv"

THREADS_NUM = 25

cache = {}

session = requests.Session()

adapter = requests.adapters.HTTPAdapter(pool_connections=THREADS_NUM, pool_maxsize=THREADS_NUM)
session.mount('https://', adapter)
session.mount('http://', adapter)

def get_points(id):
    if id in cache:
        return cache[id]
    
    r = session.get(URL.format(id), headers={"X-Requested-With": "XMLHttpRequest"})    
    soup = bs.BeautifulSoup(r.text, 'html.parser')

    initial = soup.find('p', class_='dettagli')
    if not initial:
        return (None, None, id)
    
    done = soup.find('p', class_='dettagli_r')
    if not done:
        return (None, None, id)
    
    initial = initial.text.split(",")[0].strip().replace(".", "")
    done = done.text.split(",")[0].strip().replace(".", "")
    return int(initial), int(done), id

def load_cache():
    try:
        with open(CACHE_FILE, "r") as f:
            for line in f:
                initial, done, id = line.strip().split(",")
                if initial == "None" or done == "None":
                    cache[int(id)] = (None, None, int(id))
                else:
                    cache[int(id)] = (int(initial), int(done), int(id))
    except FileNotFoundError:
        pass

def main():
    load_cache()
    earning = 0
    losing = 0
    with Pool(THREADS_NUM) as pool:
        # Set miniters to avoid automatic tqdm estimation (broken because of cache initial burst)
        res = tqdm(pool.imap_unordered(get_points, range(START_ID, MAX_ID)), initial=MAX_ID-START_ID, miniters=1)
        with open(CACHE_FILE, "w") as f:
            # Dump map iterator
            res = (r for r in res if f.write(f"{r[0]},{r[1]},{r[2]}\n"))
            res = (r for r in res if r[0] is not None)

            for initial, done, id in res:
                reduced = (initial + done) * (1 - REDUCTION)
                if done > reduced:
                    earning += 1
                    if initial > 100:
                        print(f"Player {id} is earning with {done} points out of {initial} (reduced: {reduced:.2f})")
                else:
                    losing += 1

    print(f"Got {earning + losing} results out of {MAX_ID-START_ID} requests")
    print(f"Earning: {earning}, Losing: {losing}")


if __name__ == "__main__":
    main()
