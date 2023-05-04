from threading import Thread, Lock, Event, Semaphore
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout
from collections import deque
import requests as req
from tqdm import tqdm
import signal
import bs4
import time

N_THREADS = 200

im_blocked = Event()

punteggio = 0
punteggio_lock = Lock()

time_list = deque()
time_list.append(time.time())
MAX_LIST_LEN = 200

keybord_interrupt = Event()

threads_list_lock = Lock()
threads = []

final_join = Semaphore(0)

def get_speed():
    if time.time() - time_list[0] == 0:
        return 0

    time_span = time.time() - time_list[0]
    fraction_second = 1 / time_span
    return len(time_list) * fraction_second

def increment_speed_counter():
    time_list.append(time.time())
    if len(time_list) > MAX_LIST_LEN:
        time_list.popleft()

def start_new_thread(index):

    while im_blocked.is_set() and not keybord_interrupt.is_set():
        time.sleep(.1)

    if(keybord_interrupt.is_set()):
        final_join.release()
        return

    t = Thread(target=do_request, args=(index,))
    with threads_list_lock:
        threads[index] = t

    t.start()
    increment_speed_counter()

def do_request(index):

    try:
        req.post(
            url='http://cetto5inc2022.altervista.org/pages/guess.php',
            cookies={'PHPSESSID': ''},
            data={
                'guessValue': '1',
                'modelValue': '2',
                'imageValue': '1',
                'difficulty': '0',
                'imageIndex': '2037'
            },
            timeout=30
        )
    except ConnectionError:
        if not im_blocked.is_set() and not keybord_interrupt.is_set():      
            im_blocked.set()
            print('blocked')
    except (ConnectTimeout, ReadTimeout):
        pass
    except Exception as e:
        print(e)
        print(type(e))

    start_new_thread(index)


def get_punteggio():
    url_punteggio = 'http://cetto5inc2022.altervista.org/pages/users.php'
    r = req.get(url_punteggio)
    soup = bs4.BeautifulSoup(r.text, 'html.parser')

    # find the row of a table with a td containing the username
    row = soup.find('td', text='samu').parent
    # take the third td
    td = row.find_all('td')[2]
    punteggio = td.text
    return int(punteggio)

def target_punteggio_updater():
    global punteggio
    while not keybord_interrupt.is_set():
        try:
            tmp = get_punteggio()
            with punteggio_lock:
                punteggio = tmp
        except:
            pass
        time.sleep(1)
    print('punteggio updater stopped')

updater = Thread(target=target_punteggio_updater)
updater.start()

threads = [Thread(target=start_new_thread, args=(i,)) for i in range(N_THREADS)]
for t in tqdm(threads, desc="starting..."):
    t.start()
    time.sleep(.001)

try:
    while True:
        if im_blocked.is_set():
            for _ in tqdm(range(50), desc='waiting', leave=False):
                time.sleep(.1)
            im_blocked.clear()

        with punteggio_lock:
            print(
                'points:', punteggio,
                'speed:',str(int(get_speed())).zfill(5) , 
                '#'*int(get_speed()/10)
                )
except KeyboardInterrupt:
    print('Stopping...')
    keybord_interrupt.set()
    for _ in tqdm(range(N_THREADS), desc='waiting threads to finish', leave=False):
        final_join.acquire()
    updater.join()
    for i in threads:
        i.join()
    