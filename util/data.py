import json
import os
from typing import Any, Iterable, TypedDict

from questionary import ValidationError, confirm

from network.networkmanager import Cloud
from util.printer import print_white
from util.validator import IPValidator

# TODO: `file_name` variable should be used a class default
file_name = "data.json"


class MigrationRequired(Exception):
    pass


class ConfigDataType(TypedDict, total=False):
    token: str | None
    blacklist: dict[str, str]
    custom_ips: dict[str, str]
    friends: dict[str, str]


# TODO: Use magic methods `__enter__` and `__exit__`
class ConfigData:
    """
    Abstraction of the configuration storage implemented in a singleton-like way to have easy global access and avoid re-reads
    :var instance: Global instance of the internal class for the data source
    :vartype instance: __DataSource
    """

    class __DataSource:
        def __init__(self, data_file: str):
            self.data_file = data_file
            self.data: ConfigDataType = {"token": None}
            if os.path.isfile(data_file):
                with open(self.data_file, "r") as file:
                    self.data = json.load(file)
            else:
                self.__create()

            self.token = self.data.get("token", None)

        def save(self) -> None:
            if not os.path.isfile(self.data_file):
                self.__create()
            with open(self.data_file, "w") as file:
                json.dump(self.data, file, indent=4)

        def __create(self) -> None:
            with open(self.data_file, "w") as write_file:
                json.dump(self.data, write_file, indent=4)

    instance: __DataSource

    def __init__(self, data_file: str):
        """
        Instantiate the data source item if it isn't defined already.
        :param data_file: Config file path
        :vartype data_file: str
        """
        if not hasattr(ConfigData, "instance"):
            ConfigData.instance = ConfigData.__DataSource(data_file)

    def get(self, key, default=None):
        """
        Retrieve data from the configuration
        :param key: Key to find in the config data
        :param default: Value to return if key is not present
        :return: Appropiate value or None
        """
        return self.instance.data.get(key, default)

    def set(self, key, value) -> None:
        """
        Set data to configuration
        :param key: Key to store the data on the config
        :param value: Value to store
        """
        self.instance.data[key] = value  # type: ignore[literal-required]

    def save(self) -> None:
        """
        Store the changes made on memory to the data file
        """
        if self.instance:
            self.instance.save()

    def __iter__(self):
        return iter(self.instance.data.items()) if self.instance else iter({}.items())


class CustomList(ConfigData):
    """
    Extra lists to store on the configuration data
    """

    def __init__(self, name: str):
        """
        Retrieves or initializes the list with specified name
        :param name: List name
        """
        super().__init__(name)
        self.name = name
        possible_data = self.instance.data.get(name, None)
        if isinstance(possible_data, dict):
            self.data = possible_data
        else:
            self.data = {}
            self.instance.data[self.name] = self.data  # type: ignore[literal-required]
            self.save()
        if type(self.data) is list:
            raise MigrationRequired("Need to update to using dicts")

    def __contains__(self, key):
        return key in self.data

    def __iter__(self) -> Iterable[tuple[str, Any]]:
        return iter(self.data.items())

    def __len__(self) -> int:
        return len(self.data)

    def add(self, key, value) -> None:
        """
        Add item to the list
        :param key: Key to store the data on the list
        :param value: Value to store
        :return: None
        """
        self.data[key] = value

    def get(self, key, default=None):
        """
        Retrieve data from the list
        :param key: Key identifying the data to retrieve
        :param default: Value to return if Key is not found on the list
        :return: Appropiate data from the list or default
        """
        return self.data.get(key, default)

    def has(self, value, key: str = "name") -> bool:
        """
        Check if item exists from the list by it's key property value
        """
        items = self.find_all(value, key)
        return bool(items)

    def find(self, value, key="name"):
        """
        Retrieve the first item from the list by it's key property value
        :param value: Value to find
        :param key: Name of the attribute to compare with
        :return: The item or None
        """
        items = self.find_all(value, key)
        return items[0] if items else (None, None)

    def find_all(self, value, key="name"):
        """
        Retrieve all items from the list whose key property equals value
        :param value: Value to find
        :param key: Name of the attribute to compare with
        :return: List with all the items matching
        """
        return [(k, val) for k, val in self.data.items() if val.get(key, None) == value]

    def pop(self, key, default=None):
        """
        Retrieve and delete an item from the list
        :param key: Key identifying the item to retrieve
        :param default: Value to return if Key is not found on the list
        :return: Appropiate item from the list or default
        """
        return self.data.pop(key, default)

    def delete(self, key) -> None:
        """
        Delete an item from the list
        :param key: Key identifying the item to delete
        :return: None
        """
        self.pop(key, None)


def update_cloud_friends() -> CustomList:
    """
    Get the list of approved friends from cloud
    :return: Dict of cloud friends
    """
    config = ConfigData(file_name)
    friends = CustomList("friends")
    token = config.get("token", None)
    runner = Cloud(token)
    cloud_friends_list = runner.get_friends()
    for friend in cloud_friends_list:
        ip, f = friends.find(friend.get("name"))
        friend_item = {"name": friend.get("name"), "enabled": False}
        if f:
            friend_item = f
            friends.delete(ip)
        friends.add(friend.get("ip"), friend_item)
    if isinstance(friends.data, dict):
        missing = [
            key
            for key, friend in friends.data.items()
            if all(
                cloud_friend.get("name") != friend.get("name")
                for cloud_friend in cloud_friends_list
            )
        ]
        for key in missing:
            friends.delete(key)
    config.save()
    return friends


def migrate_to_dict() -> None:
    """
    Aux function to migrate if old data file is being used
    """
    error = False
    config = ConfigData(file_name)
    for key, value in config:
        if isinstance(value, list):
            d = {}
            for item in value:
                try:
                    ip = item.pop("ip")
                    ip_calc = IPValidator.validate_get(ip)
                    if ip != ip_calc:
                        item["value"] = ip
                    d[ip_calc] = item
                except ValidationError as e:
                    print_white(e.message)
                    delete = confirm("Do you want to delete it").ask()
                    print(delete)
                    if not delete:
                        error = True
                    continue
            config.set(key, d)
    if not error:
        config.save()
        print_white("Config files required migration, please restart the program.")
    else:
        print_white(
            "Issues found in some items, delete or fix them manually to proceed."
        )
