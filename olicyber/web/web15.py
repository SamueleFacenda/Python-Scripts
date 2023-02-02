from bs4 import BeautifulSoup
import requests as req

base_url = "http://web-15.challs.olicyber.it/"
page = req.get(base_url)
soup = BeautifulSoup(page.text, "html.parser")
external_links = []
for link in soup.find_all('rel'):
    if link.get('href').startswith('http'):
        external_links.append(link.get('href'))
for script in soup("script"):
    external_links.append(base_url + script.get('src'))

flag = ''
for ext in external_links:
    page = req.get(ext).text
    split = page.split('flag{')
    if len(split) > 1:
        flag =split[1].split('}')[0]
        break

print('flag{' + flag + '}')