import pyautogui
import keyboard
from mss.windows import MSS as mss
import time

def scartoQuadraticoMedio(a, b):
    return sum(((aa - b) ** 2 for aa in a)) / len(a)


print('Move to the left side(3sec)')
time.sleep(3)
lx, ly = pyautogui.position()

print('Move to the right side(3sec)')
time.sleep(3)
rx, ry = pyautogui.position()


print('Move on the left side leaf(3sec)')
time.sleep(3)
leaf = pyautogui.position()

print('Move on the ski(3sec)')
time.sleep(3)
# get screenshot and get pointed pixel color
with mss() as sct:
    ski = pyautogui.position()
    region = {'top': ski[1], 'left': ski[0], 'width': 1, 'height': 1}
    skiImg = sct.grab(region).raw[0]

print('Move on restart(3sec)')
time.sleep(3)
restart = pyautogui.position()
print('Starting...')
pyautogui.moveTo(restart[0], restart[1])
pyautogui.click()
time.sleep(0.5)
print("press 'q' or 'space_bar' to exit")
region = {'top': leaf[1]-5, 'left': leaf[0]-5, 'width': 10, 'height': 10}
with mss() as sct:
    while True:
        if keyboard.is_pressed('q') or keyboard.is_pressed(' '):
            break

        # detect leaf on left
        leftImg = sct.grab(region).raw
        leftok = scartoQuadraticoMedio(leftImg, skiImg)
        print(leftok)

        if leftok < 10:
            print('left')
            pyautogui.moveTo(lx, ly)
        else:
            print('right')
            pyautogui.moveTo(rx, ry)
        pyautogui.click()
        time.sleep(0.18)
