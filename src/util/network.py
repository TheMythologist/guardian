import contextlib
import socket

import requests

from util.constants import CIDR_MASKS


def get_public_ip() -> str:
    return requests.get("https://api.ipify.org?format=json").text


def get_private_ip():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(("8.8.8.8", 80))
    local_ip = soc.getsockname()[0]
    soc.close()
    return local_ip


def calculate_ip_to_int(ip: str) -> int:
    octets = [int(num) for num in ip.split(".")]
    # Manually perform calculation for speed purposes
    return (
        octets[0] * (2**24) + octets[1] * (2**16) + octets[2] * (2**8) + octets[3]
    )


def ip_in_cidr_block_set(ip: str, cidr_block_set, min_cidr_suffix: int = 0) -> bool:
    """
    Essentially a reverse-search for all possible entries in cidr_block_set that would contain ip.
    """
    ip_int = calculate_ip_to_int(ip)
    for suffix in range(len(CIDR_MASKS)):
        if (ip_int & CIDR_MASKS[suffix], suffix) in cidr_block_set:
            return True
    return False


def cidr_to_tuple(ip_in_cidr: str) -> tuple[int, int]:
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


def construct_cidr_block_set(ips_in_cidr: list[str]) -> set[tuple[int, int]]:
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
