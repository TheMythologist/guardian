"""
Simple workaround that sets the current working directory to wherever Guardian.exe exists,
instead of wherever the console was launched from. Functions like open() use the working directory
as a base for any local paths specified, so if the working directory isn't as expected then files get
saved in the wrong location (e.g. on the Desktop if you launched Guardian from a console that had its'
path currently at the Desktop).
"""

from os import chdir  # chdir to change working directory
from sys import argv


def wd_fix():
    # if argv is empty for some reason then can't fix
    if len(argv) < 1:
        return False

    path_to_exe = argv[0]
    try:
        chdir(
            path_to_exe[: path_to_exe.rindex("\\")]
        )  # "go up one folder" by removing the last folder from the path
    except (OSError, ValueError):
        return False
