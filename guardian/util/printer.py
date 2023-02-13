from textwrap import fill

from colorama import Fore


def print_white(msg: str) -> None:
    print(Fore.LIGHTWHITE_EX + msg + Fore.RESET)


def print_invalid_ip(address: str) -> None:
    print_white(f'Invalid IP: "{Fore.LIGHTCYAN_EX}{address}{Fore.RESET}"')


def pretty_print(string: str) -> None:
    for paragraph in string.split("\n"):
        print(fill(paragraph), end="\n\n")
