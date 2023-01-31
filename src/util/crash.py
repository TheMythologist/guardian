import time
import traceback
from typing import Optional


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
