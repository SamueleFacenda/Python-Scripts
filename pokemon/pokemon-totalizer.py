import pandas
from sys import argv

file = "pokedex.csv" if len(argv)==1 else argv[1]

df = pandas.read_csv(file)
df.Total = df.HP + df.Attack + df.Defense + df['Sp. Atk'] + df['Sp. Def'] + df.Speed
print(df.head())
df.to_csv(file, index=True)
