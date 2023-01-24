import ipaddress
import timeit


def old_cidr_to_tuple(ip_in_cidr: str) -> tuple[int, int]:
    is_one_digit_suffix = ip_in_cidr[-2] == "/"
    suffix_int = int(ip_in_cidr[-1:]) if is_one_digit_suffix else int(ip_in_cidr[-2:])
    ip_str = ip_in_cidr[:-2] if is_one_digit_suffix else ip_in_cidr[:-3]
    ip_int = int(ipaddress.IPv4Address(ip_str))

    return ip_int, suffix_int


def new_cidr_to_tuple(ip_in_cidr: str) -> tuple[int, int]:
    ip_str, _, suffix_int = ip_in_cidr.partition("/")
    octets = [int(num) for num in ip_str.split(".")]
    ip_int = (
        octets[0] * (2**24) + octets[1] * (2**16) + octets[2] * (2**8) + octets[3]
    )

    return ip_int, int(suffix_int)


# TODO: Is using py-radix faster?
def test_code(fun):
    assert fun("52.102.136.0/24") == (879134720, 24)


if __name__ == "__main__":
    old_speed = timeit.timeit(lambda: test_code(old_cidr_to_tuple), number=100000)
    print(f"Old speed: {old_speed}")
    new_speed = timeit.timeit(lambda: test_code(new_cidr_to_tuple), number=100000)
    print(f"New speed: {new_speed}")
    # More than double the speed!
