import requests as r
from bs4 import BeautifulSoup as bs, Comment

url = 'http://web-14.challs.olicyber.it/'
text = r.get(url).text
soup = bs(text, 'html.parser')
flag = ''
# find all comments
for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
    print(comment)