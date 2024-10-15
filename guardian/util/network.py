import contextlib
import socket
from typing import cast

import requests

from util.constants import CIDR_MASKS
from util.types import CIDR_BLOCK


def get_public_ip() -> str:
    return requests.get("https://api.ipify.org").text


def get_private_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soc:
        soc.connect(("8.8.8.8", 80))
        local_ip = soc.getsockname()[0]
    return cast(str, local_ip)


def calculate_ip_to_int(ip: str) -> int:
    octets = [int(num) for num in ip.split(".")]
    # Manually perform calculation for speed purposes
    return octets[0] * (2**24) + octets[1] * (2**16) + octets[2] * (2**8) + octets[3]


# TODO: Convert all CIDR notation into integers (by chopping off the subnet mask part). Then, store all these integers
# in a set. Then, to see if an IP is within a CIDR range, we will need to construct all CIDR blocks containing that IP.
# This can be done by converting the IP to an integer and then apply each mask with bitwise AND.

# To generate all CIDR blocks containing a certain IP, we must zero the right-most bit, append /32, then zero the next
# right-most bit (move one bit left), append /31, and so on.


def ip_in_cidr_block_set(ip: str, cidr_block_set: set[CIDR_BLOCK]) -> bool:
    """
    Essentially a reverse-search for all possible entries in cidr_block_set that would contain ip.
    """
    ip_int = calculate_ip_to_int(ip)
    for suffix in range(len(CIDR_MASKS)):
        if (ip_int & CIDR_MASKS[suffix], suffix) in cidr_block_set:
            return True
    return False


def cidr_to_tuple(ip_in_cidr: str) -> CIDR_BLOCK:
    """
    Converts a string representing an IP in CIDR notation to two integers,
    the first integer represents the lowest IP in the CIDR block,
    and the second integer represents the mask (just the suffix)

    NOTE: Does *not* check for the validity of a CIDR block. Example, 255.255.255.255/1 would be accepted, but is not
    a valid CIDR block.
    """
    ip, suffix = ip_in_cidr.split("/")
    suffix_int = int(suffix)
    return calculate_ip_to_int(ip), suffix_int


def construct_cidr_block_set(ips_in_cidr: list[str]) -> set[CIDR_BLOCK]:
    """
    Construct a set of IPs in CIDR notation. This set is specifically optimised to only work with the
    ip_in_cidr_block_set() function.

    Ignores any element which is not valid IPv4 CIDR notation (as long as it was still a string).
    """
    ip_set = set()
    for ip_cidr in ips_in_cidr:
        with contextlib.suppress(ValueError):
            # [0] is IP as integer, [1] is subnet mask in /xy notation (only xy)
            ip_set.add(cidr_to_tuple(ip_cidr))
    return ip_set
