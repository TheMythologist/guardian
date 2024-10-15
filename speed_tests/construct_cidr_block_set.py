import contextlib
import ipaddress
import re
import timeit

ipv4_network_cidr_regex = re.compile(
    r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|/[0-3]?\d)){4}"
)


def cidr_to_tuple(ip_in_cidr: str) -> tuple[int, int]:
    ip_str, _, suffix = ip_in_cidr.partition("/")
    suffix_int = int(suffix)
    octets = [int(num) for num in ip_str.split(".")]
    ip_int = octets[0] * (2**24) + octets[1] * (2**16) + octets[2] * (2**8) + octets[3]
    return ip_int, suffix_int


def new_construct_cidr_block_set(ips_in_cidr):
    return {
        cidr_to_tuple(ip_cidr)
        for ip_cidr in ips_in_cidr
        if ipv4_network_cidr_regex.fullmatch(ip_cidr)
    }


def old_construct_cidr_block_set(ips_in_cidr):
    ip_set = set()
    for ip_cidr in ips_in_cidr:
        # IndexError if string too short
        # ValueError if `int()` conversion failed
        # AddressValueError if invalid IPv4 address
        with contextlib.suppress(IndexError, ValueError, ipaddress.AddressValueError):
            # [0] is IP as integer, [1] is subnet mask in /xy notation (only xy)
            ip_tuple = cidr_to_tuple(ip_cidr)
            ip_set.add(ip_tuple)
    return ip_set


def test_code(fun):
    tests = [
        "192.168.0.1/0",
        "192.168.0.1/1",
        "192.168.0.1/2",
        "192.168.0.1/3",
        "192.168.0.1/4",
        "192.168.0.1/5",
        "192.168.0.1/6",
        "192.168.0.1/7",
        "192.168.0.1/8",
        "192.168.0.1/9",
        "192.168.0.1/10",
        "192.168.0.1/11",
        "192.168.0.1/12",
        "192.168.0.1/13",
        "192.168.0.1/14",
        "192.168.0.1/15",
        "192.168.0.1/16",
        "192.168.0.1/17",
        "192.168.0.1/18",
        "192.168.0.1/19",
        "192.168.0.1/20",
        "192.168.0.1/21",
        "192.168.0.1/22",
        "192.168.0.1/23",
        "192.168.0.1/24",
        "192.168.0.1/25",
        "192.168.0.1/26",
        "192.168.0.1/27",
        "192.168.0.1/28",
        "192.168.0.1/29",
        "192.168.0.1/30",
        "192.168.0.1/31",
        "192.168.0.1/32",
    ]
    assert fun(tests) == {
        (3232235521, 9),
        (3232235521, 12),
        (3232235521, 18),
        (3232235521, 15),
        (3232235521, 21),
        (3232235521, 27),
        (3232235521, 24),
        (3232235521, 30),
        (3232235521, 2),
        (3232235521, 8),
        (3232235521, 5),
        (3232235521, 11),
        (3232235521, 14),
        (3232235521, 20),
        (3232235521, 17),
        (3232235521, 23),
        (3232235521, 26),
        (3232235521, 32),
        (3232235521, 29),
        (3232235521, 1),
        (3232235521, 4),
        (3232235521, 7),
        (3232235521, 13),
        (3232235521, 10),
        (3232235521, 16),
        (3232235521, 19),
        (3232235521, 25),
        (3232235521, 22),
        (3232235521, 28),
        (3232235521, 31),
        (3232235521, 0),
        (3232235521, 6),
        (3232235521, 3),
    }


if __name__ == "__main__":
    old_speed = timeit.timeit(
        lambda: test_code(old_construct_cidr_block_set), number=10000
    )
    print(f"Old speed: {old_speed}")
    new_speed = timeit.timeit(
        lambda: test_code(new_construct_cidr_block_set), number=10000
    )
    print(f"New speed: {new_speed}")
    print("Speed-up failed :(")
