import json
import os
from typing import TypedDict

from util.singleton import Singleton


class ConfigDataType(TypedDict):
    blacklist: dict[str, str]
    whitelist: dict[str, str]


class ConfigData(Singleton):
    def __init__(self, data_file: str = "data.json"):
        self.data_file = data_file
        self.data: ConfigDataType
        if os.path.isfile(data_file):
            self.load()
        else:
            self.data = {"blacklist": {}, "whitelist": {}}
            self.save()

    def load(self) -> None:
        with open(self.data_file, "r") as file:
            self.data = json.load(file)

    def save(self) -> None:
        with open(self.data_file, "w") as file:
            json.dump(self.data, file, indent=4)

    def get(self, key: str, default=None):
        """
        Retrieve data from the configuration
        :param key: Key to find in the config data
        :param default: Value to return if key is not present
        :return: Appropiate value or None
        """
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        """
        Set data to configuration
        :param key: Key to store the data on the config
        :param value: Value to store
        """
        self.data[key] = value  # type: ignore[literal-required]
