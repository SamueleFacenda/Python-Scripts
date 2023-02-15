from Crypto.Cipher import AES
from Crypto.Random.random import randint
from hashlib import sha256
from tqdm import trange, tqdm
import socket
from threading import Thread, Event, active_count

HOST = '2fapp.challs.olicyber.it' 
PORT = 12207

def inf():
    while True:
        yield 1

def expand_pin(pin):
    return sha256(pin).digest()[:16]

pswHex = 'a' * 32
passfrase = bytes.fromhex(pswHex)
pins = [str(i).zfill(6).encode() for i in range(1000000)]
pins = [(pin, expand_pin(pin)) for pin in pins]
decoded = {}
for pin, expanded in tqdm(pins, leave=False, desc="Encrypting all pins"):
    c1 = AES.new(expanded, AES.MODE_ECB)
    decoded[c1.decrypt(passfrase).hex()] = pin

run_event = Event()

def tryLuck():
    out = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"3\nadmin\n" + pswHex.encode() + b"\n")
        s.recv(127)
        data = s.recv(60)
        token = data.split(b'\n')[0][-32:]
        if token in decoded:
            # run_event.set()
            pin = decoded[token]
            print("User pin: ", pin)
            s.sendall(b"2\nadmin\n" + pin.encode() + b"\n" + pin.encode() + b"\n")
            with open('flag.txt', 'wb') as f:
                while True:
                    data = s.recv(1024)
                    if not data:
                        break
                    f.write(data)
            out = True
    return out

MAX_THREADS = 1000

for _ in tqdm(inf(), leave=False, desc="Trying all pins", total=1000000):
    if run_event.is_set():
        break
    t = Thread(target=tryLuck)
    t.start()
    while active_count() > MAX_THREADS:
        pass
#    t = Thread(target=tryLuck)
#    t.start()
