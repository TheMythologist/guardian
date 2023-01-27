import socket

import requests


def get_public_ip() -> str:
    return requests.get("https://api.ipify.org?format=json").text


def get_private_ip():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(("8.8.8.8", 80))
    local_ip = soc.getsockname()[0]
    soc.close()
    return local_ip
