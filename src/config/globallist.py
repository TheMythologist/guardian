from typing import Any, Iterable

from config.configdata import ConfigData
from util.singleton import Singleton


class GlobalList:
    """Stores a dictionary mapping from IP address to name.
    Used for whitelisting or blacklisting IP addresses
    """

    def __init__(self, list_name: str):
        self.list_name = list_name
        self.config = ConfigData()
        # Sample self.data: {"192.168.0.1", "bad guy"}
        self.load()

    @property
    def ips(self) -> list[str]:
        return list(self.data.keys())

    @property
    def names(self) -> list[str]:
        return list(self.data.values())

    def __contains__(self, key: str) -> bool:
        return key in self.data

    def __iter__(self) -> Iterable[tuple[str, Any]]:
        return iter(self.data.items())

    def __len__(self) -> int:
        return len(self.data)

    def add(self, ip: str, name: str) -> None:
        self.data[ip] = name

    def get(self, ip: str, default=None):
        return self.data.get(ip, default)

    def has(self, name: str) -> bool:
        """Check if name is present in the list."""
        return name in self.names

    def find(self, name: str) -> str | None:
        """Gets the ip address based on the name."""
        return self.ips[self.names.index(name)] if self.has(name) else None

    def remove(self, ip: str) -> None:
        self.data.pop(ip)

    def save(self) -> None:
        self.config.set(self.list_name, self.data)
        self.config.save()

    def load(self) -> None:
        self.data: dict = self.config.get(self.list_name, {})

    def reload(self) -> None:
        self.load()


class Whitelist(GlobalList, metaclass=Singleton):
    def __init__(self) -> None:
        super().__init__("whitelist")


class Blacklist(GlobalList, metaclass=Singleton):
    def __init__(self) -> None:
        super().__init__("blacklist")
