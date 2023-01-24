import contextlib
import ipaddress
import json
import os.path
import re
import time

import prsw
import requests

# This file contains classes and methods to manage acquiring, parsing, and updating a possibly dynamic list of IP ranges
# that Guardian needs to be aware of. Such ranges include R* / T2 official IPs, as well as IPs that can be used for
# miscellaneous R* Services, such as Microsoft Azure.


class ScrapeError(BaseException):
    """Could not scrape the HTML for data for some reason."""


ripe = prsw.RIPEstat()
try:
    T2_EU = {peer.prefix.compressed for peer in ripe.announced_prefixes(202021)}
    T2_US = {peer.prefix.compressed for peer in ripe.announced_prefixes(46555)}
except ConnectionError:
    # https://whois.ipip.net/AS202021
    T2_EU = {
        "185.56.64.0/24",
        "185.56.64.0/22",
        "185.56.65.0/24",
        "185.56.66.0/24",
        "185.56.67.0/24",
    }

    # https://whois.ipip.net/AS46555
    T2_US = {
        "104.255.104.0/24",
        "104.255.104.0/22",
        "104.255.105.0/24",
        "104.255.106.0/24",
        "104.255.107.0/24",
        "192.81.240.0/24",
        "192.81.240.0/22",
        "192.81.241.0/24",
        "192.81.242.0/24",
        "192.81.243.0/24",
        "192.81.244.0/24",
        "192.81.244.0/22",
        "192.81.245.0/24",
        "192.81.246.0/24",
        "192.81.247.0/24",
        "198.133.210.0/24",
    }

# This URL should return information about the most up-to-date JSON file containing Azure IP ranges.
# Microsoft claims that a new file is published every 7 days, and that any new IPs will not be used for another 7 days.
# Note that we could also possibly manually generate the URL if necessary.
# I'm not very good at web development so idk what the best practice is for this lol
AZURE_GET_PUBLIC_CLOUD_URL = (
    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
)
# The regex pattern to find download files on the page.
MICROSOFT_DOWNLOAD_REGEX = re.compile(
    r"https://download\.microsoft\.com/download[^\"]*\.json"
)


def determine_best_azure_file(urls: list[str]) -> tuple[str, bytes]:
    """
    Given multiple azure URLs, identify the best JSON file to return based on the largest changeNumber
    Returns the URL, and the contents of the JSON file as bytes
    """
    # Return only the JSON file with the highest changeNumber
    highest_change_number = 0
    best_response = b""
    best_url = ""
    for url in urls:
        content = get_azure_ip_file_from_url(url)
        change_number = json.loads(content)["changeNumber"]
        if change_number > highest_change_number:
            highest_change_number = change_number
            best_response = content
            best_url = url
    return best_url, best_response


def get_azure_ip_ranges_download(
    page_to_search: str = AZURE_GET_PUBLIC_CLOUD_URL,
) -> tuple[str, bytes]:
    """
    Finds the URL to the most recent JSON file. I looked it up and yes, apparently, there is no actual API that allows
    requesting the most up-to-date ranges. We have to download the human-readable page, then parse / search through the
    HTML response to find the link.

    This method is *meant* to be comprehensive and robust enough to not break if Microsoft changes the HTML content of
    their pages. When this code was written, the download file occurred multiple times in the HTML page, but it was the
    only URL to match the regular expression.

    If multiple possibly valid files were found on the page, only the file with the highest changeNumber will be returned.
    """

    # Get the actual page.
    try:
        response = requests.get(page_to_search)
        response.raise_for_status()  # If there was an error code, raise it.
        if response.status_code != 200:
            raise ScrapeError(
                f"URL to scrape returned {response.status_code} instead of 200.",
                response,
            )

        # Search through the HTML for all download.microsoft.com JSON files.
        re_files = re.findall(MICROSOFT_DOWNLOAD_REGEX, str(response.content))
        if re_files is None:
            raise ScrapeError(
                "Did not find any valid download URLs while searching the page.",
                response,
            )

        files = list(set(re_files))
        return determine_best_azure_file(files)

    except (ScrapeError, requests.exceptions.RequestException) as e:
        # For whatever reason, we couldn't find a file to download. We can attempt to generate the URL manually.
        # TODO: Figure out what times (and timezones) Microsoft publish their IP ranges at.
        raise e


def construct_all_cidr_masks():
    all_ones = 0b11111111111111111111111111111111
    masks = [all_ones]
    masks.extend(masks[-1] << 1 & all_ones for _ in range(32))
    masks.reverse()
    return masks


CIDR_MASKS = construct_all_cidr_masks()

# TODO: Convert all CIDR notation into integers (by chopping off the subnet mask part). Then, store all these integers
# in a set. Then, to see if an IP is within a CIDR range, we will need to construct all CIDR blocks containing that IP.
# This can be done by converting the IP to an integer and then apply each mask with bitwise AND.

# To generate all CIDR blocks containing a certain IP, we must zero the right-most bit, append /32, then zero the next
# right-most bit (move one bit left), append /31, and so on.
# Probably best manipulated using ipaddress.packed attribute?


def parse_azure_ip_ranges_from_url(url_to_json_file):
    """
    Given a Microsoft Azure IP .JSON file, parses the file and returns an array of strings of CIDR ranges
    that may be used by R* Services.
    """
    response = requests.get(url_to_json_file)
    response.raise_for_status()  # Can't handle anything here. If we can't download the file, it's game over.

    # Parse the response and return it to be saved
    return parse_azure_ip_ranges(response.content)


def get_azure_ip_file_from_url(url_to_json_file):
    # TODO: Provide some sanity checks to see if the file contains the content we expect.
    response = requests.get(url_to_json_file)
    response.raise_for_status()
    return response.content


def save_azure_file(data_to_save, where_to_save="db.json"):
    with open(where_to_save, mode="wb") as file:
        bytes_written = file.write(data_to_save)
    return bytes_written


def azure_file_add_timestamp(azure_file, filename):
    # keep the line breaks
    as_list = azure_file.splitlines(True)
    now = str(time.time())
    # add timestamp and filename (should be formatted the same as the actual file)
    as_list.insert(1, b'  "acquiredFrom": "' + bytes(filename, "utf-8") + b'",\n')
    as_list.insert(1, b'  "acquiredWhen": ' + bytes(now, "utf-8") + b",\n")
    return b"".join(as_list)


def parse_azure_ip_ranges(azure_file):
    azure_cloud_json = json.loads(azure_file)
    categories = azure_cloud_json["values"]
    arr_ranges = next(
        (
            cat["properties"]["addressPrefixes"]
            for cat in categories
            if cat["name"] == "AzureCloud"
        ),
        None,
    )
    if arr_ranges is None:
        raise ValueError("Could not find AzureCloud category in values array.")
    return arr_ranges


def parse_azure_ip_ranges_from_file(location_of_file):
    with open(location_of_file, mode="rb") as file:
        return parse_azure_ip_ranges(file.read())


def calculate_ip_int(ip: str) -> int:
    octets = [int(num) for num in ip.split(".")]
    # Manually perform calculation of suffix_int for speed purposes
    return (
        octets[0] * (2**24) + octets[1] * (2**16) + octets[2] * (2**8) + octets[3]
    )


def cidr_to_tuple(ip_in_cidr: str) -> tuple[int, int]:
    """
    Converts a string representing an IP in CIDR notation to two integers,
    the first integer represents the lowest IP in the CIDR block,
    and the second integer represents the mask (just the suffix)

    NOTE: Does *not* check for the validity of a CIDR block. Example, 255.255.255.255/1 would be accepted, but is not
    a valid CIDR block.
    """
    ip_str, _, suffix = ip_in_cidr.partition("/")
    suffix_int = int(suffix)
    # Manually perform calculation of suffix_int for speed purposes
    ip_int = calculate_ip_int(ip_str)
    return ip_int, suffix_int


def construct_cidr_block_set(ips_in_cidr):
    """
    Construct a set of IPs in CIDR notation. This set is specifically optimised to only work with the
    ip_in_cidr_block_set() function.

    Ignores any element which is not valid IPv4 CIDR notation (as long as it was still a string).
    """
    ip_set = set()
    for ip_cidr in ips_in_cidr:
        with contextlib.suppress(ValueError):
            # [0] is IP as integer, [1] is subnet mask in /xy notation (only xy)
            ip_tuple = cidr_to_tuple(ip_cidr)
            ip_set.add(ip_tuple)
    return ip_set


def get_dynamic_blacklist(backup_file="db.json"):
    # TODO: It seems like we can determine if a range has changed by looking at the 'changeNumber' attribute
    # for a given category, however, there unfortunately doesn't appear to be any sort of timestamp included
    # in the actual JSON file. We'll probably need to save the timestamp manually by adding it to the JSON?
    # TL;DR the problem is that we can tell if the file has been updated by checking `changeNumber`, but that requires
    # attempting to download the file anyways. Ideally, we want to be able to skip trying to download all together
    # because the method isn't entirely reliable, and also fallback to the previously saved version if the download
    # fails.
    # ranges = set()

    try:
        download_link, content = get_azure_ip_ranges_download()
        ranges = parse_azure_ip_ranges(content)
        # If we got here, then the ranges are *probably* okay.
        save_azure_file(azure_file_add_timestamp(content, download_link), backup_file)
        ranges.extend(T2_EU)  # add R* EU ranges
        ranges.extend(T2_US)  # add R* US ranges
    except Exception as e:
        print("ERROR: Could not parse Azure ranges from URL. Reason: ", e)
        if not os.path.isfile(backup_file):
            raise FileNotFoundError(
                f"ERROR: Could not find backup file {backup_file}."
            ) from e
        ranges = parse_azure_ip_ranges_from_file(backup_file)
    return construct_cidr_block_set(ranges)


def ip_in_cidr_block_set(ip, cidr_block_set, min_cidr_suffix=0):
    """
    Essentially a reverse-search for all possible entries in cidr_block_set that would contain ip.
    """
    ip_int = calculate_ip_int(ip)
    return any(
        (ip_int & CIDR_MASKS[suffix], suffix) in cidr_block_set
        for suffix in range(min_cidr_suffix, len(CIDR_MASKS))
    )


# Tries to find places where an IP occurs in the azure info.
def reverse_search_ip_in_azure(ip, azure_info_json):
    search = []  # where categories will be added
    categories = azure_info_json["values"]
    # categories is a list of dictionaries
    for cat in categories:
        ranges = cat["properties"]["addressPrefixes"]
        for str_cidr in ranges:
            # Ignore invalid IPv4 addresses
            with contextlib.suppress(ipaddress.AddressValueError):
                cidr = ipaddress.IPv4Network(str_cidr)
                if ipaddress.IPv4Address(ip) in cidr:
                    search.append(cat)
    return search


def get_cidr_suffixes(array_of_cidr):
    cidrs = set()
    for entry in array_of_cidr:
        # Ignore invalid IPv4 addresses
        with contextlib.suppress(ipaddress.AddressValueError):
            ipaddress.IPv4Network(entry)  # lazy way of seeing if it's a valid ipv4
            cidrs.add(entry[-2:])
    return cidrs


if __name__ == "__main__":
    # dl = get_azure_ip_ranges_download()
    # ips_test = parse_azure_ip_ranges_from_url(dl[0])
    get_dynamic_blacklist("db_test.json")
