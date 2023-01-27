from typing import Any, Iterable

from config.ConfigData import ConfigData


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
        # TODO: Cleanup checking of `isinstance` (can no longer be a list)
        if isinstance(possible_data, dict):
            self.data = possible_data
        else:
            self.data = {}
            self.instance.data[self.name] = self.data  # type: ignore[literal-required]
            self.save()

    def __contains__(self, key) -> bool:
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
