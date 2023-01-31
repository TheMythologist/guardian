import questionary

from config.globallist import Blacklist, Whitelist
from util.constants import UI_STYLE
from validator.ip import IPInBlacklist, IPInWhitelist
from validator.name import NameInBlacklist, NameInWhitelist


class Lists:
    ip_validators = {Whitelist: IPInWhitelist, Blacklist: IPInBlacklist}
    name_validators = {Whitelist: NameInWhitelist, Blacklist: NameInBlacklist}

    @staticmethod
    def choose_list():
        while True:
            answer = questionary.select(
                "Which list do you want to edit?",
                [
                    {"name": "Whitelist", "value": Whitelist},
                    {"name": "Blacklist", "value": Blacklist},
                    {"name": "Go back", "value": "return"},
                ],
                style=UI_STYLE,
            ).ask()
            if not answer or answer == "return":
                break
            Lists.edit_list(answer)

    @staticmethod
    def edit_list(global_list_type: type[Whitelist | Blacklist]):
        while True:
            answer = questionary.select(
                f"What do you want to do with {global_list_type.__name__}?",
                [
                    {"name": "List", "value": Lists.list},
                    {"name": "Add", "value": Lists.add},
                    {"name": "Edit", "value": Lists.edit},
                    {"name": "Delete", "value": Lists.delete},
                    {"name": "Go back", "value": "return"},
                ],
                style=UI_STYLE,
            ).ask()
            if not answer or answer == "return":
                break
            answer(global_list_type)

    @staticmethod
    def add(global_list_type: type[Whitelist | Blacklist]):
        global_list = global_list_type()
        name = questionary.text(
            "Name", style=UI_STYLE, validate=Lists.name_validators[global_list_type]
        ).ask()
        ip = questionary.text(
            "IP address", style=UI_STYLE, validate=Lists.ip_validators[global_list_type]
        ).ask()
        global_list.add(ip, name)
        global_list.save()

    @staticmethod
    def list(global_list_type: type[Whitelist | Blacklist]):
        global_list = global_list_type()
        if len(global_list):
            for ip, name in global_list:  # type: ignore[attr-defined]
                print(f"IP Address: {ip}\tName: {name}")
        else:
            print(f"No {global_list_type.__name__} entries")

    @staticmethod
    def edit(global_list_type: type[Whitelist | Blacklist]):
        global_list = global_list_type()
        while True:
            name = questionary.select(
                "Which entry do you want to edit?",
                global_list.names,
                style=UI_STYLE,
            ).ask()
            ip = global_list.find(name)
            new_name = questionary.text("Name", style=UI_STYLE, default=name).ask()
            new_ip = questionary.text(
                "IP address",
                style=UI_STYLE,
                default=ip,  # type: ignore[arg-type]
                validate=Lists.ip_validators[global_list_type],
            ).ask()
            global_list.remove(ip)  # type: ignore[arg-type]
            global_list.add(new_ip, new_name)
            global_list.save()
            break

    @staticmethod
    def delete(global_list_type: type[Whitelist | Blacklist]):
        global_list = global_list_type()
        name = questionary.select(
            "Which entry do you want to edit?",
            global_list.names,
            style=UI_STYLE,
        ).ask()
        ip = global_list.find(name)
        global_list.remove(ip)  # type: ignore[arg-type]
        global_list.save()
