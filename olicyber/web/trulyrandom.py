import time
import hmac
import hashlib
import random
import string
import datetime
import requests as r

url = 'http://trulyrandomsignature.challs.olicyber.it/'

s = r.Session()
resp = s.get(url)
uptime = int(resp.headers['X-Uptime'])
print(f'Uptime: {uptime}')

username = s.cookies.get('user')
signature = s.cookies.get('signature')

def get_random_string(length):
  letters = string.ascii_lowercase
  result_str = ''.join(random.choice(letters) for i in range(length))
  return result_str

def sign(text, key):
  textAsBytes = bytes(text, encoding='ascii')
  keyAsBytes  = bytes(key, encoding='ascii')
  signature = hmac.new(keyAsBytes, textAsBytes, hashlib.sha256)
  return signature.hexdigest()


start_time = time.time() - uptime-1
seed = datetime.datetime.utcfromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
print(f'Seed: {seed}')
random.seed(seed)

SUPER_SECRET_KEY = get_random_string(32)
print(f'SUPER_SECRET_KEY: {SUPER_SECRET_KEY}')

target_admin = 'admin'
target_signature = sign(target_admin, SUPER_SECRET_KEY)
print(f'Target signature: {target_signature}')

print('Check my signature:')
if sign(username, SUPER_SECRET_KEY) == signature:
    print('Correct!')
else:
    print('Wrong!')

resp = r.get(url + '/admin', cookies={'user': target_admin, 'signature': target_signature})
print(resp.text)
