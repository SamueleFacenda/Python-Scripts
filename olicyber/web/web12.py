import requests as r
from bs4 import BeautifulSoup as bs

url = 'http://web-12.challs.olicyber.it/'
text = r.get(url).text
soup = bs(text, 'html.parser')
for p in soup.find_all('p'):
    if 'flag' in p.text:
        print(p.text)
        break