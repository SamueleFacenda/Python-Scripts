import requests as r
from bs4 import BeautifulSoup as bs

url = 'http://web-13.challs.olicyber.it/'
text = r.get(url).text
soup = bs(text, 'html.parser')
flag = ''
for p in soup.find_all('span', {'class': 'red'}):
    flag += p.text
print(flag)