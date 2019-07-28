import os
import json
from network.networkmanager import Cloud

data_file = 'data.json'


def create_file():
    data = {
        'custom_ips': [],
        'blacklist': [],
        'config': [],
        'friends': [],
        'token': None
    }

    with open(data_file, "w") as write_file:
        json.dump(data, write_file, indent=2)


def read_file():
    if not os.path.isfile(data_file):
        create_file()
    with open(data_file, "r") as file:
        data = json.load(file)
    if not data.get('blacklist'):
        data['blacklist'] = []
        data = save_file(data)
    return data


def save_file(data):
    if not os.path.isfile(data_file):
        create_file()
    with open(data_file, "w") as file:
        json.dump(data, file, indent=2)
    return data


def cloud_friends():
    config = read_file()
    token = config['token']
    runner = Cloud(token)
    code, r = runner.get_friends()
    for friend in r.get('friends'):
        d = [x for x in config['friends'] if x.get('name') == friend.get('name')]
        if d:
            d[0]['ip'] = friend.get('ip')
        else:
            config['friends'].append({'name': friend.get('name'), 'ip': friend.get('ip'), 'enabled': False})
    for friend in config['friends']:
        if not any(d.get('name') == friend.get('name') for d in r.get('friends')):
            config['friends'][:] = [d for d in config['friends'] if d.get('name') == r.get('friends')]
    save_file(config)
    return config.get('friends')
