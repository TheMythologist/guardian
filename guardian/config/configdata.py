import json
from pathlib import Path
from typing import Any, Literal, TypedDict, TypeVar

from util.singleton import Singleton

LIST_TYPE = Literal["blacklist", "whitelist"]
T = TypeVar("T", bound=dict[str, str])


class ConfigDataType(TypedDict):
    blacklist: dict[str, str]
    whitelist: dict[str, str]


class ConfigData(metaclass=Singleton):
    def __init__(self, data_file: str = "data.json"):
        self.data_file = Path(data_file)
        self.data: ConfigDataType
        if self.data_file.is_file():
            self.load()
        else:
            self.data = {"blacklist": {}, "whitelist": {}}
            self.save()

    def load(self) -> None:
        with self.data_file.open("r") as file:
            self.data = json.load(file)

    def save(self) -> None:
        with self.data_file.open("w") as file:
            json.dump(self.data, file, indent=4)

    def get(self, key: LIST_TYPE, default: Any | T = None) -> Any | T:
        """
        Retrieve data from the configuration
        :param key: Key to find in the config data
        :param default: Value to return if key is not present
        :return: Appropiate value or None
        """
        return self.data.get(key, default)

    def set(self, key: LIST_TYPE, value: T) -> None:
        """
        Set data to configuration
        :param key: Key to store the data on the config
        :param value: Value to store
        """
        self.data[key] = value
