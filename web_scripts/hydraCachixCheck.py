import requests as r
from tqdm import tqdm
from multiprocessing.pool import ThreadPool as Pool

### Checks what store paths are not in cachix

THREADS = 10

HYDRA_URL = 'https://hydra.nix-community.org'
CACHIX_URL = 'https://nix-community.cachix.org'
HEADERS = {'Content-Type': 'application/json'}

PROJECT = 'nixpkgs' # optional if eval is not 'latest'
JOBSET = 'cuda-stable' # optional if eval is not 'latest'
EVAL = 'latest'

def get_latest_eval():
    url = f'{HYDRA_URL}/jobset/{PROJECT}/{JOBSET}/evals'
    response = r.get(url, headers=HEADERS).json()
    return response['evals'][0]['id']

def get_eval_builds(eval=EVAL):
    url = f'{HYDRA_URL}/eval/{eval}/builds'
    response = r.get(url, headers=HEADERS).json()
    return response

def get_store_paths(builds):
    paths = []
    for build in builds:
        if build['buildstatus'] != 0:
            continue
        store_path = build['buildoutputs']['out']['path']
        name = build['nixname']
        paths.append((name, store_path))
    return paths

def check_cachix(path):
    path = path.split('/')[-1].split('-')[0]
    url = f'{CACHIX_URL}/{path}.narinfo'
    response = r.get(url, headers=HEADERS)
    return response.status_code == 200

def get_cachix_statuses(paths):
    paths = [x[1] for x in paths]
    with Pool(THREADS) as pool:
        statuses = pool.imap(check_cachix, paths)
        statuses = list(tqdm(statuses, total=len(paths)))
    return list(zip(paths, statuses))

def main():
    eval = get_latest_eval() if EVAL == 'latest' else EVAL
    builds = get_eval_builds(eval)
    paths = get_store_paths(builds)
    statuses = get_cachix_statuses(paths)
    statuses.sort(key=lambda x: not x[1])
    for name, status in statuses:
        print(f'{name}: {"cached" if status else "not cached"}')
    

if __name__ == '__main__':
    main()