import ipaddress  # woah, this is a default module? neat.

"""
This file contains classes and methods to manage acquiring, parsing, and updating a possibly dynamic list of IP ranges
that Guardian needs to be aware of. Such ranges include R* / T2 official IPs, as well as IPs that can be used for
miscellaneous R* Services, such as Microsoft Azure.
"""

# TODO: Find an API we can use to get these ranges dynamically. If necessary, these ones can be used as a fallback,
#  as I don't think these ranges change often.

# https://whois.ipip.net/AS202021
T2_EU = {"185.56.64.0/24", "185.56.64.0/22", "185.56.65.0/24", "185.56.66.0/24", "185.56.67.0/24"}

# https://whois.ipip.net/AS46555
T2_US = {"104.255.104.0/24", "104.255.104.0/22", "104.255.105.0/24", "104.255.106.0/24", "104.255.107.0/24",
         "192.81.240.0/24", "192.81.240.0/22", "192.81.241.0/24", "192.81.242.0/24", "192.81.243.0/24",
         "192.81.244.0/24", "192.81.244.0/22", "192.81.245.0/24", "192.81.246.0/24", "192.81.247.0/24",
         "198.133.210.0/24"}


def get_all_ips_from_cidr(ip_in_cidr_notation):
    ips = set()
    ip_range = ipaddress.IPv4Network(ip_in_cidr_notation)
    for ip in ip_range:
        ips.add(str(ip))

    return ips


def get_all_ips_from_cidr_array(array_of_ip_in_cidr_notation):
    ips = set()
    for ip_range in array_of_ip_in_cidr_notation:
        ips = ips.union(get_all_ips_from_cidr(ip_range))

    return ips


if __name__ == "__main__":
    print(get_all_ips_from_cidr("185.56.64.0/24"))
    print(len(get_all_ips_from_cidr_array(["185.56.64.0/24", "185.56.64.0/22"])))