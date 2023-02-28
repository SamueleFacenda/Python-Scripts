#!/bin/python3

import time
import pyautogui

s = 10 
while True:
    s = -s
    pyautogui.move(0,s) 
    time.sleep(20)
    
