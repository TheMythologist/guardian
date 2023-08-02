from ctypes import WinDLL, create_unicode_buffer

kernel32 = WinDLL("kernel32", use_last_error=True)


def get_console_title() -> str:
    BUF_SIZE = 256
    buffer = create_unicode_buffer(256)
    kernel32.GetConsoleTitleW(buffer, BUF_SIZE)
    return buffer.value


def set_console_title(title: str) -> None:
    kernel32.SetConsoleTitleW(title)


def get_original_console_title() -> str:
    return get_console_title().split(" - ")[0]
