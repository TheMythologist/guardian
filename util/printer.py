from colorama import Fore


def print_white(msg):
    print(Fore.LIGHTWHITE_EX + msg + Fore.RESET)


# TODO: Use `__enter__` for running messages
def print_running_message(session: str):
    print_white(
        f'Running: "{Fore.LIGHTCYAN_EX}{session} session{Fore.LIGHTWHITE_EX}" Press "{Fore.LIGHTCYAN_EX}CTRL + C{Fore.LIGHTWHITE_EX}" to stop.'
    )


def print_stopped_message(session: str):
    print_white(f'Stopped: "{Fore.LIGHTCYAN_EX}{session} session{Fore.LIGHTWHITE_EX}"')


def print_invalid_ip(ip):
    print_white(f'Not valid IP or URL: "{Fore.LIGHTCYAN_EX}{ip}{Fore.LIGHTWHITE_EX}"')
