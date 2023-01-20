import pandas

df = pandas.read_csv('pokedex.csv', index_col=False)
df.Total = df.HP + df.Attack + df.Defense + df['Sp. Atk'] + df['Sp. Def'] + df.Speed
print(df.head())
df.to_csv('pokedex.csv', index=False)