import os
import json
from network.networkmanager import Cloud
file_name = 'data.json'


class MigrationRequired(Exception):
    pass


class ConfigData:
    instance = None

    class __DataSource:
        def __init__(self, data_file):
            self.data_file = data_file
            self.data = {
                'config': {},
                'token': None
            }
            if not os.path.isfile(data_file):
                self.__create()
            else:
                with open(self.data_file, "r") as file:
                    self.data = json.load(file)

            self.token = self.data.get('token', None)

        def save(self):
            if not os.path.isfile(self.data_file):
                self.__create()
            with open(self.data_file, "w") as file:
                json.dump(self.data, file, indent=4)

        def __create(self):
            with open(self.data_file, "w") as write_file:
                json.dump(self.data, write_file, indent=4)

    def __init__(self, data_file):
        if not ConfigData.instance:
            ConfigData.instance = ConfigData.__DataSource(data_file)

    def get(self, key, default=None):
        return self.instance.data.get(key, default)

    def set(self, key, value):
        self.instance.data[key] = value

    def save(self):
        if self.instance:
            self.instance.save()

    def __iter__(self):
        return iter(self.instance.data.items()) if self.instance else iter({}.items())


class CustomList(ConfigData):
    def __init__(self, name):
        super().__init__(None)
        self.name = name
        self.data = self.instance.data.get(name, None) if self.instance else None
        if type(self.data) is list:
            raise MigrationRequired("Need to update to using dicts")
        if not self.data:
            self.data = {}
            self.instance.data[self.name] = self.data
            self.save()

    def __contains__(self, key):
        return key in self.data

    def __iter__(self):
        return iter(self.data.items())

    def __len__(self):
        return len(self.data)

    def add(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)

    def find(self, value, key='name'):
        items = self.find_all(value, key)
        return items[0] if items else None

    def find_all(self, value, key='name'):
        return [(k, val) for k, val in self.data.items() if val.get(key, None) == value]

    def pop(self, key, default=None):
        return self.data.pop(key, default)

    def delete(self, key):
        self.pop(key, None)


def update_cloud_friends():
    config = ConfigData(file_name)
    friends = CustomList('friends')
    token = config.get('token', None)
    runner = Cloud(token)
    cloud_friends_list = runner.get_friends()
    for friend in cloud_friends_list:
        ip, f = friends.find(friend.get('name'))
        friend_item = {'name': friend.get('name'), 'enabled': False}
        if f:
            friend_item = f
            friends.delete(ip)
        friends.add(friend.get('ip'), friend_item)
    missing = list()
    for key, friend in friends.data.items():
        if not any(cloud_friend.get('name') == friend.get('name') for cloud_friend in cloud_friends_list):
            missing.append(key)
    for key in missing:
        friends.delete(key)
    friends.save()
    return friends


def migrate_to_dict():
    config = ConfigData(file_name)
    for key, value in config:
        if type(value) is list:
            d = {}
            for item in value:
                ip = item.pop('ip')
                d[ip] = item
            config.set(key, d)
    config.save()
