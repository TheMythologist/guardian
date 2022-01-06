import ipaddress    # woah, this is a default module? neat.
import requests     # to get the microsoft azure ip ranges
import re    # to search through the html to find the file (because there's currently no API to automate getting ranges)
import json         # to parse the file once it's been downloaded
from sys import getsizeof  # for debug testing to determine the size of certain things
import time         # timing

"""
This file contains classes and methods to manage acquiring, parsing, and updating a possibly dynamic list of IP ranges
that Guardian needs to be aware of. Such ranges include R* / T2 official IPs, as well as IPs that can be used for
miscellaneous R* Services, such as Microsoft Azure.
"""


class ScrapeError(BaseException):
    """ Could not scrape the HTML for data for some reason. """


# TODO: Find an API we can use to get these ranges dynamically. If necessary, these ones can be used as a fallback,
#  as I don't think these ranges change often.
# https://whois.ipip.net/AS202021
T2_EU = {"185.56.64.0/24", "185.56.64.0/22", "185.56.65.0/24", "185.56.66.0/24", "185.56.67.0/24"}

# https://whois.ipip.net/AS46555
T2_US = {"104.255.104.0/24", "104.255.104.0/22", "104.255.105.0/24", "104.255.106.0/24", "104.255.107.0/24",
         "192.81.240.0/24", "192.81.240.0/22", "192.81.241.0/24", "192.81.242.0/24", "192.81.243.0/24",
         "192.81.244.0/24", "192.81.244.0/22", "192.81.245.0/24", "192.81.246.0/24", "192.81.247.0/24",
         "198.133.210.0/24"}

# This URL should return information about the most up-to-date JSON file containing Azure IP ranges.
# Microsoft claims that a new file is published every 7 days, and that any new IPs will not be used for another 7 days.
# Note that we could also possibly manually generate the URL if necessary.
# I'm not very good at web development so idk what the best practice is for this lol
AZURE_GET_PUBLIC_CLOUD_URL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
# The regex pattern to find download files on the page.
MICROSOFT_DOWNLOAD_REGEX = re.compile('https://download.microsoft.com/download[^"]*[.]json')


def get_azure_ip_ranges_download(page_to_search=AZURE_GET_PUBLIC_CLOUD_URL):
    """
    Finds the URL to the most recent JSON file. I looked it up and yes, apparently, there is no actual API that allows
    requesting the most up-to-date ranges. We have to download the human-readable page, then parse / search through the
    HTML response to find the link.

    This method is *meant* to be comprehensive and robust enough to not break if Microsoft changes the HTML content of
    their pages. When this code was written, the download file occurred multiple times in the HTML page, but it was the
    only URL to match the regular expression.

    If multiple possibly valid files were found on the page, they will all be returned.
    """

    # Get the actual page.
    try:
        response = requests.get(page_to_search)
        response.raise_for_status()  # If there was an error code, raise it.
        #if response.status_code != 200:
        #    raise ScrapeError("URL to scrape returned " + str(response.status_code) + " instead of 200.", response)

        # Search through the HTML for all download.microsoft.com JSON files.
        files = re.findall(MICROSOFT_DOWNLOAD_REGEX, str(response.content))
        if files is None:
            raise ScrapeError("Did not find any valid download URLs while searching the page.", response)

        files = list(set(files))  # Removes any duplicate finds.
        return files

    except (ScrapeError, requests.exceptions.RequestException) as e:
        """ For whatever reason, we couldn't find a file to download. We can attempt to generate the URL manually. """
        # TODO: Figure out what times (and timezones) Microsoft publish their IP ranges at.
        raise e


def construct_all_cidr_masks():
    all_ones = 4294967295  # 0b11111111111111111111111111111111
    masks = [all_ones]
    for _ in range(32):
        masks.append((masks[len(masks) - 1] << 1) & all_ones)
    masks.reverse()
    return masks


CIDR_MASKS = construct_all_cidr_masks()

# TODO: Convert all CIDR notation into integers (by chopping off the subnet mask part). Then, store all these integers
#  in a set. Then, to see if an IP is within a CIDR range, we will need to construct all CIDR blocks containing that IP.
#  This can be done by converting the IP to an integer and then apply each mask with bitwise AND.

"""
To generate all CIDR blocks containing a certain IP, we must zero the right-most bit, append /32, then zero the next
right-most bit (move one bit left), append /31, and so on.
Probably best manipulated using ipaddress.packed attribute?
"""


def generate_all_cidr_containing_ip(ip, min_cidr=0):
    ip_num = int(ipaddress.IPv4Address(ip))  # convert to number
    ips = []
    for index in range(min_cidr, len(CIDR_MASKS)):  # index into CIDR_MASKS
        ips.append(ip_num & CIDR_MASKS[index])
    return ips


def parse_azure_ip_ranges(url_to_json_file):
    """
    Given a Microsoft Azure IP .JSON file, parses the file and returns an array of strings of CIDR ranges
    that may be used by R* Services.
    """
    response = requests.get(url_to_json_file)
    response.raise_for_status()  # Can't handle anything here. If we can't download the file, it's game over.
    # TODO: Using reverse_search_ip_in_azure() indicates that R* Services use the generic 'AzureCloud' category.
    #  A bit boring but to be expected and hey, at least they're actually in the file.
    #  So, need to get the address ranges (they're CIDR) from that category and return a set of IPs to compare against.
    azure_cloud_json = json.loads(response.content)
    categories = azure_cloud_json['values']
    arr_ranges = None
    for cat in categories:
        if cat['name'] == 'AzureCloud':
            arr_ranges = cat['properties']['addressPrefixes']
            break
    if arr_ranges is None:
        raise ValueError("Could not find AzureCloud category in values array.")
    #ips = get_all_ips_from_cidr_array(arr_ranges)
    #return ips
    return arr_ranges


def cidr_to_tuple(ip_in_cidr):
    """
    Converts a string representing an IP in CIDR notation to two integers,
    the first integer represents the lowest IP in the CIDR block,
    and the second integer represents the mask (just the suffix)

    NOTE: Does *not* check for the validity of a CIDR block. Example, 255.255.255.255/1 would be accepted, but is not
    a valid CIDR block.
    """
    """
    Calculating the suffix seems weird, but it's best explained with an example. Let's say you have the CIDR block
    111.22.3.44/9. Here, the suffix is only 1 digit (i.e. 1 character in the string), and we can determine this by
    seeing if the second-last character was the slash. If the second-last character isn't a slash, it must be a number,
    in which case the IP address is something like 111.22.3.44/29. We then take either those one or two digits, and
    convert it to an integer.
    """
    is_one_digit_suffix = ip_in_cidr[-2] == "/"
    suffix_int = int(ip_in_cidr[-1:]) if is_one_digit_suffix else int(ip_in_cidr[-2:])
    ip_str = ip_in_cidr[:-2] if is_one_digit_suffix else ip_in_cidr[:-3]
    ip_int = int(ipaddress.IPv4Address(ip_str))

    return ip_int, suffix_int


def construct_cidr_block_set(ips_in_cidr):
    """
    Construct a set of IPs in CIDR notation. This set is specifically optimised to only work with the
    ip_in_cidr_block_set() function.

    Ignores any element which is not valid IPv4 CIDR notation (as long as it was still a string).
    """
    ip_set = set()
    for ip_cidr in ips_in_cidr:
        try:
            ip_tuple = cidr_to_tuple(ip_cidr)  # [0] is IP as integer, [1] is subnet mask in /xy notation (only xy)
            ip_set.add(ip_tuple)
        except (IndexError, ValueError, ipaddress.AddressValueError):
            """ IndexError if string too short, ValueError if int() conversion failed, AddressValueError if not IPv4.
                In any case, just ignore the element. """
            pass

    return ip_set

def get_dynamic_blacklist():
    download_link = get_azure_ip_ranges_download()
    ranges = parse_azure_ip_ranges(download_link[0])  # TODO: Handle multiple download files!
    ranges.extend(T2_EU)    # add R* EU ranges
    ranges.extend(T2_US)    # add R* US ranges
    dynamic_blacklist = construct_cidr_block_set(ranges)
    return dynamic_blacklist


def ip_in_cidr_block_set(ip, cidr_block_set, min_cidr_suffix=0):
    """
    Essentially a reverse-search for all possible entries in cidr_block_set that would contain ip.
    """
    ip_int = int(ipaddress.IPv4Address(ip))
    for suffix in range(min_cidr_suffix, len(CIDR_MASKS)):
        # try each subnet mask
        if (ip_int & CIDR_MASKS[suffix], suffix) in cidr_block_set:
            return True

    return False  # "brute-force" searched against all possible subnet masks, didn't find a match


def get_all_ips_from_cidr(ip_in_cidr_notation):
    ips = list()
    #print("generating IPs")
    ip_range = ipaddress.IPv4Network(ip_in_cidr_notation)
    for ip in ip_range:
        #print("adding " + str(ip))
        ips.append(str(ip))

    return ips


def get_all_ips_from_cidr_array(array_of_ip_in_cidr_notation):
    ips = set()
    for ip_range in array_of_ip_in_cidr_notation:
        try:
            ips = ips.union(get_all_ips_from_cidr(ip_range))
        except ipaddress.AddressValueError:
            pass  # element ignored because it wasn't valid IPv4

    return ips


# Tries to find places where an IP occurs in the azure info.
def reverse_search_ip_in_azure(ip, azure_info_json):
    search = []  # where categories will be added
    categories = azure_info_json['values']
    # categories is a list of dictionaries
    for cat in categories:
        ranges = cat['properties']['addressPrefixes']
        for str_cidr in ranges:
            try:
                cidr = ipaddress.IPv4Network(str_cidr)
                if ipaddress.IPv4Address(ip) in cidr:
                    search.append(cat)
            except ipaddress.AddressValueError:
                pass  # not an IPv4 CIDR range. couldn't find an "is IPv4" / "is CIDR" function
    return search


def get_cidr_suffixes(array_of_cidr):
    cidrs = set()
    for entry in array_of_cidr:
        try:
            ipaddress.IPv4Network(entry)  # lazy way of seeing if it's a valid ipv4
            cidrs.add(entry[-2:])
        except ipaddress.AddressValueError:  # not ipv4
            pass

    return cidrs

if __name__ == "__main__":
    #print(get_all_ips_from_cidr("185.56.64.0/24"))
    #print(len(get_all_ips_from_cidr_array(["185.56.64.0/24", "185.56.64.0/22"])))
    dl = get_azure_ip_ranges_download()
    print(dl)
    start = time.perf_counter()
    ips_test = parse_azure_ip_ranges(dl[0])
    finish = time.perf_counter()
    print("size:", getsizeof(ips_test), "len:", len(ips_test), "seconds:", (finish - start) / 1000)
    # size: 1073742040 len: 21838185, time: like 90 minutes or something, shouldn't have used perf counter here I guess

