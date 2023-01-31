import ctypes
import logging
import sys
import time
import traceback
from multiprocessing import freeze_support
from typing import Optional

import pydivert
from prompt_toolkit.styles import Style

from config.configdata import ConfigData
from config.globallist import Blacklist, Whitelist
from menu.menu import Menu
from util.printer import print_white

__version__ = "3.3.1"

logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(filename="history.log")
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s][%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

debug_logger = logging.getLogger("debugger")
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler("debugger.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s][%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
debug_logger.addHandler(fh)

LF_FACESIZE = 32
STD_OUTPUT_HANDLE = -11

style = Style(
    [
        ("qmark", "fg:#00FFFF bold"),  # token in front of the question
        ("question", "bold"),  # question text
        ("answer", "fg:#00FFFF bold"),  # submitted answer text behind the question
        ("pointer", "fg:#00FFFF bold"),  # pointer used in select and checkbox prompts
        ("selected", "fg:#FFFFFF bold"),  # style for a selected item of a checkbox
        ("separator", "fg:#00FFFF"),  # separator in lists
        ("instruction", ""),  # user instructions for select, rawselect, checkbox
    ]
)


def crash_report(
    exception: Exception,
    additional: Optional[str] = None,
    filename: Optional[str] = None,
) -> None:
    if filename is None:
        filename = f"crashreport_{hex(int(time.time_ns()))[2:]}.log"

    with open(filename, "w") as handle:
        handle.write(
            f"Report local time: {time.asctime(time.localtime())}\nReport UTC time:   {time.asctime(time.gmtime())}\n\n"
        )
        handle.write(f"Error: {exception}\n\n")
        handle.write(f"{traceback.format_exc()}\n")

        if additional is not None:
            handle.write(f"\nAdditional info: {additional}\n")


if __name__ == "__main__":
    freeze_support()

    try:
        # Initialise singleton objects for thread-safety
        config = ConfigData()
        blacklist = Blacklist()
        whitelist = Whitelist()

        logger.info("Init")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print_white("Please restart as administrator")
            logger.info("Started without admin")
            input("Press enter to exit.")
            sys.exit()
        logger.info("Booting up")
        print_white("Booting up...")
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        ctypes.windll.kernel32.SetConsoleTitleW(f"Guardian {__version__}")
    except Exception as e:
        crash_report(e, "Guardian crashed before reaching main()")
        raise

    try:
        Menu.main_menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        crash_report(e, "Guardian crashed in main()")
        raise
