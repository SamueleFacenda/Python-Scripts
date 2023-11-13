import pyautogui
import time
import keyboard

print("move to tsuki location! You have three seconds!")
time.sleep(3)
x, y = pyautogui.position()
print("x: " + str(x) + " y: " + str(y))
print("press 'q' or 'space_bar' to exit")
pyautogui.moveTo(x, y)

while True:
    if keyboard.is_pressed('q') or keyboard.is_pressed(' '):
        break

    pyautogui.click() 
    time.sleep(0.2)

print("Exited!")
