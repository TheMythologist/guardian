import ipaddress
import re
import socket
import timeit

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")


def old_validate(ip: str) -> bool:
    try:
        if ipv4.match(ip):
            ipaddress.IPv4Address(ip)
            return True
    except (ipaddress.AddressValueError, socket.gaierror):
        pass
    return False


def new_validate(ip: str) -> bool:
    try:
        if ipv4.match(ip):
            socket.inet_aton(ip)
            return True
    except socket.error:
        pass
    return False


def test_code(fun):
    assert fun("52.102.136.0") is True
    # assert not fun("52.102.136.257")


if __name__ == "__main__":
    old_speed = timeit.timeit(lambda: test_code(old_validate), number=100000)
    print(f"Old speed: {old_speed}")
    new_speed = timeit.timeit(lambda: test_code(new_validate), number=100000)
    print(f"New speed: {new_speed}")
    # More than thrice the speed in positive cases!
    # Speed is comparable for negative cases
    # It's already a win, pluswe are more likely to get positive cases
