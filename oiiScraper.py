from bs4 import BeautifulSoup
from tqdm import trange
from selenium import webdriver 
from selenium.webdriver import Chrome 
from selenium.webdriver.chrome.service import Service 
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

url = 'https://training.olinfo.it/#/ranking/'

# il 02/02/2023
n_pages = 999

options = webdriver.ChromeOptions() 
options.headless = True
options.page_load_strategy = 'none' 
chrome_path = './chromedriver.exe'
chrome_service = Service(chrome_path) 
browser = Chrome(options=options, service=chrome_service) 
#browser.implicitly_wait(5)

total_points = 0

try:
    for i in trange(1,n_pages + 1):
        tmp_page_points = 0
        browser.get(url + str(i))
        tags = []
        while len(tags) != 20:
            soup = BeautifulSoup(browser.page_source,"html.parser")
            tags = soup.find_all('tt')
        for tag in tags:
            content = tag.text
            tmp_page_points += int(content)
        total_points += tmp_page_points
except KeyboardInterrupt:
    print('exiting')
    print(f'{total_points=} {tmp_page_points=}')

browser.close()
print(f'{total_points=}')
# total = 6260568
