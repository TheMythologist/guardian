import json
import re
import time
from pathlib import Path

import prsw
import requests

from util.network import construct_cidr_block_set

# This file contains classes and methods to manage acquiring, parsing, and updating a possibly dynamic list of IP ranges
# that Guardian needs to be aware of. Such ranges include R* / T2 official IPs, as well as IPs that can be used for
# miscellaneous R* Services, such as Microsoft Azure.


class ScrapeError(Exception):
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
        response = requests.get(url)
        response.raise_for_status()
        content = response.content
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
        response = requests.get(
            page_to_search, headers={"User-Agent": "Guardian - GTA5 Firewall"}
        )
        response.raise_for_status()
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
        # TODO: attempt to generate the URL manually.
        # TODO: Figure out what times (and timezones) Microsoft publish their IP ranges at.
        raise e


def azure_file_add_timestamp(azure_file_contents: bytes, filename: str) -> bytes:
    as_list = azure_file_contents.splitlines(True)
    # add timestamp and filename (should be formatted the same as the actual file)
    as_list.insert(1, f'  "acquiredFrom": "{filename}",\n'.encode())
    as_list.insert(1, f'  "acquiredWhen": "{time.time()}",\n'.encode())
    return b"".join(as_list)


def parse_azure_ip_ranges(azure_file_contents: bytes) -> list[str]:
    azure_cloud_json = json.loads(azure_file_contents)
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


def get_dynamic_blacklist(backup_file: str = "db.json") -> set[tuple[int, int]]:
    # TODO: We can tell if the file has been updated by checking `changeNumber`, but that requires attempting
    # to download the file anyways. Ideally, we want to be able to skip trying to download all together because
    # the method isn't entirely reliable, and also fallback to the previously saved version if the download fails.

    backup_path = Path(backup_file)
    try:
        download_link, content = get_azure_ip_ranges_download()
        ranges = parse_azure_ip_ranges(content)
        backup_path.write_bytes(azure_file_add_timestamp(content, download_link))
        ranges.extend(T2_EU)  # add R* EU ranges
        ranges.extend(T2_US)  # add R* US ranges
    except Exception as e:
        print("ERROR: Could not parse Azure ranges from URL. Reason: ", e)
        if not Path(backup_file).is_file():
            raise FileNotFoundError(
                f"ERROR: Could not find backup file {backup_file}."
            ) from e
        ranges = parse_azure_ip_ranges(backup_path.read_bytes())
    return construct_cidr_block_set(ranges)
