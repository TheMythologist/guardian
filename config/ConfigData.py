import json
import os
from typing import TypedDict

# TODO: `file_name` variable should be used a class default
file_name = "data.json"


class MigrationRequired(Exception):
    pass


class ConfigDataType(TypedDict):
    blacklist: dict[str, str]
    whitelist: dict[str, str]


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
            self.data: ConfigDataType
            if os.path.isfile(data_file):
                with open(self.data_file, "r") as file:
                    self.data = json.load(file)
            else:
                self.data = {"blacklist": {}, "whitelist": {}}
            self.save()

        def save(self) -> None:
            with open(self.data_file, "w") as file:
                json.dump(self.data, file, indent=4)

    instance: __DataSource

    def __init__(self, data_file: str):
        """
        Instantiate the data source item if it isn't defined already.
        :param data_file: Config file path
        :vartype data_file: str
        """
        if not hasattr(ConfigData, "instance"):
            ConfigData.instance = ConfigData.__DataSource(data_file)

    def get(self, key: str, default=None):
        """
        Retrieve data from the configuration
        :param key: Key to find in the config data
        :param default: Value to return if key is not present
        :return: Appropiate value or None
        """
        return self.instance.data.get(key, default)

    def set(self, key: str, value) -> None:
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
        return iter((self.instance.data if self.instance else {}).items())
