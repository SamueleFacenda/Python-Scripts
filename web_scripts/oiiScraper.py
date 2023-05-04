import requests as req

query = {'first': 0, 'last': 1, 'action': "list"}

url = 'https://training.olinfo.it/api/user'

total_users = req.post(url, json=query).json()['num']
print(f'{total_users=}')
query['last'] = total_users
users = req.post(url, json=query).json()['users']
total_points = sum([user['score'] for user in users])
print(f'{total_points=}')
# total_points=6269871