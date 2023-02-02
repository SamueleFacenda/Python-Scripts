from bs4 import BeautifulSoup
import requests as req

base_url = "http://web-16.challs.olicyber.it/"

visited = set()

# recursive search for flags in h1 tags, other pages are linked in a tags
def search(url):
    r = req.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    h1s = soup.find_all("h1")
    for h1 in h1s:
        print(h1.text)
        if "flag" in h1.text:
            print("Flag found!")
            exit()
    all = soup.find_all("a")
    for a in all:
        if a["href"] not in visited:
            visited.add(a["href"])
            search(base_url + a["href"])

search(base_url)

