import ctypes
import json
import logging
import os
import socket
import sys
import time
import traceback
import webbrowser
import zipfile
from distutils.version import StrictVersion
from multiprocessing import Manager, freeze_support

import pydivert
from colorama import Fore
from prompt_toolkit.styles import Style
from questionary import ValidationError, prompt
from requests import RequestException
from tqdm import tqdm

import util.DynamicBlacklist  # new Azure-blocking functionality
from network import networkmanager, sessioninfo
from network.blocker import (
    Whitelist,
    Blacklist,
    Locked,
    IPSyncer,
    Debugger,
    IPCollector,
)
from util.WorkingDirectoryFix import wd_fix
from util.validator import (
    NameInCustom,
    NameInBlacklist,
    IPValidator,
    IPInCustom,
    IPInBlacklist,
    ValidateToken,
)
from util.printer import (
    print_white,
    print_running_message,
    print_stopped_message,
    print_invalid_ip,
)
import data

wd_fix()

logger = logging.getLogger("guardian")
logger.propagate = False
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(filename="history.log")
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s][%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

LF_FACESIZE = 32
STD_OUTPUT_HANDLE = -11

version = "3.1.0b5"

style = Style(
    [
        ("qmark", "fg:#00FFFF bold"),  # token in front of the question
        ("question", "bold"),  # question text
        ("answer", "fg:#00FFFF bold"),  # submitted answer text behind the question
        ("pointer", "fg:#00FFFF bold"),  # pointer used in select and checkbox prompts
        ("selected", "fg:#FFFFFF bold"),  # style for a selected item of a checkbox
        ("separator", "fg:#00FFFF"),  # separator in lists
        ("instruction", ""),  # user instructions for select, rawselect, checkbox
    ]
)


def get_public_ip():
    public_ip = networkmanager.Cloud().get_ip()
    if public_ip:
        logger.info("Got a public IP")
        return public_ip
    else:
        logger.warning("Failed to get public IP")
        return False


def get_private_ip():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(("8.8.8.8", 80))
    local_ip = soc.getsockname()[0]
    soc.close()
    return local_ip


def crash_report(exception, additional=None, filename=None):
    if filename is None:
        filename = f"crashreport_{hex(int(time.time_ns()))[2:]}.log"

    with open(filename, "w") as handle:
        handle.write(
            f"Report local time: {time.asctime(time.localtime())}\nReport UTC time:   {time.asctime(time.gmtime())}\n\n"
        )
        handle.write(f"Error: {exception}\n\n")
        handle.write(f"{traceback.format_exc()}\n")

        if additional is not None:
            handle.write(f"\nAdditional info: {additional}\n")
    return


def main():
    global cloud, config, custom_ips, blacklist, friends, dynamic_blacklist
    while True:
        token = config.get("token")
        if token:
            cloud.token = token
            if cloud.check_connection():
                logger.info("Cloud online.")
                print_white("Cloud service online")

                if cloud.check_token():
                    data.update_cloud_friends()
                else:
                    logger.info("Invalid token.")
                    print_white("Token invalid")

            else:
                logger.info("Cloud offline.")
                print_white("Cloud service down")
        dynamic_blacklist_checker = (
            "Experimental" if len(dynamic_blacklist) > 0 else "Not working"
        )
        options = {
            "type": "list",
            "name": "option",
            "message": "What do you want?",
            "qmark": "@",
            "choices": [
                {"name": "Solo session               [Working]", "value": "solo"},
                {
                    "name": "Whitelisted session        [Experimental]",
                    "value": "whitelist",
                },
                {
                    "name": f"Blacklisted session        [{dynamic_blacklist_checker}]",
                    "value": "blacklist",
                },
                {
                    "name": f"Auto whitelisted session   [{dynamic_blacklist_checker}]",
                    "value": "auto_whitelist",
                },
                {
                    "name": "Locked session             [Experimental]",
                    "value": "lock_session",
                },
                {"name": "Kick unknowns              [Unstable]", "value": "kick"},
                {"name": "New session                [Working]", "value": "new"},
                {"name": "Lists", "value": "lists"},
                {
                    "name": "Kick by IP                 [Unstable]",
                    "value": "kick_by_ip",
                },
                {"name": "Token", "value": "token"},
                {"name": "Discord", "value": "discord"},
                {"name": "Support zip", "value": "support_zip"},
                {"name": "Quit", "value": "quit"},
            ],
        }
        answer = prompt(
            options,
            style=style,
        )
        if not answer:
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)
        os.system("cls")
        option = answer["option"]

        if option == "solo":
            print_white("SOLO SESSION:\n")
            print(
                "No one can connect to your game session,\n"
                "but critical R* and SocialClub activity\n"
                "will still get through.\n\n"
                "If you are in a session with any other player,\n"
                "they will lose connection to you.\n"
            )

            options = {
                "type": "list",
                "name": "option",
                "message": "Do you want to start this type of session?",
                "qmark": "@",
                "choices": [
                    {"name": "Yes, start", "value": "start"},
                    {"name": "No, go back", "value": "back"},
                ],
            }

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    logger.info("Starting solo session")
                    print_running_message("Solo")

                    packet_filter = Whitelist(ips=[])
                    try:
                        packet_filter.start()
                        while True:
                            # TODO: Patch all `time.sleep` while loops
                            time.sleep(10)
                    except KeyboardInterrupt:
                        packet_filter.stop()
                        logger.info("Stopped solo session")
                        print_stopped_message("Solo")
                        continue

        elif option == "whitelist":
            print_white("WHITELISTED SESSION:\n")
            print(
                "Only IP addresses in your Custom list\n"
                "will be allowed to connect to you.\n\n"
                "If you are the host of a session,\n"
                "anyone not on your Custom list will\n"
                "likely lose connection to the session.\n\n"
                "If you are non-host (and any player\n"
                "in the session is not on your Custom\n"
                "list), you will lose connection to everyone else.\n"
            )

            options = {
                "type": "list",
                "name": "option",
                "message": "Do you want to start this type of session?",
                "qmark": "@",
                "choices": [
                    {"name": "Yes, start", "value": "start"},
                    {"name": "No, go back", "value": "back"},
                ],
            }

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    local_ip = get_private_ip()
                    ip_set = {local_ip}
                    ip_tags = [sessioninfo.IPTag(local_ip, "LOCAL IP")]
                    public_ip = get_public_ip()
                    if public_ip:
                        ip_set.add(public_ip)
                        ip_tags.append(sessioninfo.IPTag(public_ip, "PUBLIC IP"))
                    else:
                        print_white("Failed to get Public IP, running without")

                    for ip, friend in custom_ips:
                        if friend.get("enabled"):
                            try:
                                ip_calc = IPValidator.validate_get(ip)
                                ip_set.add(ip_calc)
                                ip_tags.append(
                                    sessioninfo.IPTag(
                                        ip_calc, f"{friend.get('name')} [WHITELIST]"
                                    )
                                )
                            except ValidationError:
                                logger.warning("Not valid IP or URL: %s", ip)
                                print_invalid_ip(ip)
                                continue

                    for ip, friend in friends:
                        if friend.get("enabled"):
                            ip_set.add(ip)
                            ip_tags.append(
                                sessioninfo.IPTag(ip, f"{friend.get('name')} [CLOUD]")
                            )

                    logger.info("Starting whitelisted session with %d IPs", len(ip_set))
                    print_running_message("Whitelisted")

                    # Exposes session information, diagnostics and behaviour.
                    # manager = Manager()
                    # connection_stats = manager.list()
                    # session_info = sessioninfo.SessionInfo(manager.dict(), connection_stats, manager.Queue(), ip_tags)

                    # logger.info("ip_tags: " + str(ip_tags))
                    # logger.info("session_info: " + str(session_info))

                    # Set up packet_filter outside the try-catch so it can be safely referenced inside KeyboardInterrupt.
                    packet_filter = Whitelist(ips=ip_set)

                    print("Experimental support for Online 1.54+ developed by Speyedr.")

                    try:
                        # session_info.start()
                        packet_filter.start()
                        while True:
                            # Here is *probably* where the PacketLogger and SessionInfo classes should be managed.
                            # Every [x] milliseconds the SessionInfo class will .update() with packet info (and a new print),
                            # and the PacketLogger instance will be passed down to Whitelist() when initialized so the filter
                            # loop can add packets to the capture. Once the session has stopped, the PacketLogger will add all
                            # packets in its' memory queue to disk (or perhaps it should be sequentially writing to a file) and
                            # save that file for investigation later.
                            time.sleep(10)
                            # input()
                            # if we reach here then the user pressed ENTER
                            # webbrowser.open("https://gitlab.com/Speyedr/guardian-fastload-fix/-/issues")
                            # time.sleep(1)      # prevents the user from opening the page a ludicrous amount of times?

                            # time.sleep(0.01)
                            # print(session_info)  # display session diagnostics
                            # print(sessioninfo.generate_stats(connection_stats))
                            # session_info.process_item()
                            # os.system('cls')  # refresh console
                    except KeyboardInterrupt:
                        packet_filter.stop()
                        # session_info.stop()
                        print_stopped_message("Whitelisted")

        elif option == "blacklist":
            print_white("BLACKLISTED SESSION:\n")
            print(
                "IP addresses in your Blacklist list\n"
                "will not be allowed to connect to you.\n\n"
                "If a connection is routed through R* servers,\n"
                "that connection will also be blocked\n"
                "as a security measure.\n\n"
                "This mode is NOT RECOMMENDED as GTA Online\n"
                "has custom routing if only a handful of\n"
                "IP addresses are blocked.\n"
            )

            options = {
                "type": "list",
                "name": "option",
                "message": "Do you want to start this type of session?",
                "qmark": "@",
                "choices": [
                    {"name": "Yes, start", "value": "start"},
                    {"name": "No, go back", "value": "back"},
                ],
            }

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    local_ip = get_private_ip()
                    allowed_ips = {local_ip}
                    public_ip = get_public_ip()
                    if public_ip:
                        allowed_ips.add(public_ip)
                    else:
                        print_white("Failed to get Public IP, running without")

                    for ip, friend in custom_ips:
                        if friend.get("enabled"):
                            try:
                                ip_calc = IPValidator.validate_get(ip)
                                allowed_ips.add(ip_calc)
                            except ValidationError:
                                logger.warning("Not valid IP or URL: %s", ip)
                                print_invalid_ip(ip)
                                continue

                    for ip, friend in friends:
                        if friend.get("enabled"):
                            allowed_ips.add(ip)

                    ip_set = set()
                    for ip, item in blacklist:
                        if item.get("enabled"):
                            try:
                                ip = IPValidator.validate_get(ip)
                                ip_set.add(ip)
                            except ValidationError:
                                logger.warning("Not valid IP or URL: %s", ip)
                                print_invalid_ip(ip)
                                continue
                    logger.info(
                        "Starting blacklisted session with %d IPs", len(ip_set)
                    )
                    print_running_message("Blacklist")

                    packet_filter = Blacklist(
                        ips=ip_set, blocks=dynamic_blacklist, known_allowed=allowed_ips
                    )
                    try:
                        packet_filter.start()
                        while True:
                            time.sleep(10)
                    except KeyboardInterrupt:
                        packet_filter.stop()
                        logger.info("Stopped blacklisted session")
                        print_stopped_message("Blacklist")

        elif option == "auto_whitelist":
            print_white("AUTO WHITELISTED SESSION:\n")
            print(
                "Same as a Whitelisted session, except\n"
                "everybody currently in the session is\n"
                "temporarily added to the whitelist,\n"
                "which prevents them from being kicked.\n\n"
                "Any automatically collected IPs will be\n"
                "lost once the session ends.\n\n"
                "If Guardian detects that a player in your\n"
                "session is being routed through R* servers,\n"
                "you will be warned whether you wish to add\n"
                "this IP to the temporary whitelist.\n\n"
                "If you do decide to allow those IPs,\n"
                "your session may not properly protected.\n"
            )

            options = {
                "type": "list",
                "name": "option",
                "message": "Do you want to start this type of session?",
                "qmark": "@",
                "choices": [
                    {"name": "Yes, start", "value": "start"},
                    {"name": "No, go back", "value": "back"},
                ],
            }

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    logger.info("Starting auto whitelisted session")
                    collector = IPCollector(packet_count_min_threshold=15)
                    logger.info("Starting to collect IPs")
                    collector.start()
                    for _ in tqdm(range(10), ascii=True, desc="Collecting session"):
                        time.sleep(0.5)
                    collector.stop()
                    ip_set = set(collector.ips)
                    logger.info("Collected %d IPs", len(ip_set))
                    print("Checking for potential tunnels in collected IPs...\n")
                    potential_tunnels = set()
                    for ip in ip_set:
                        if util.DynamicBlacklist.ip_in_cidr_block_set(
                            ip, dynamic_blacklist, min_cidr_suffix=0
                        ):
                            # Ignore if user has this IP in custom whitelist.
                            if ip not in custom_ips:
                                potential_tunnels.add(ip)
                    if len(potential_tunnels) > 0:
                        c = [{"name": ip, "checked": False} for ip in potential_tunnels]
                        options = {
                            "type": "checkbox",
                            "name": "option",
                            "qmark": "@",
                            "message": "",
                            f"WARNING! Guardian has detected {len(potential_tunnels)} IP"
                            + ("" if len(potential_tunnels) == 1 else "s")
                            + " in your current session that may be used for "
                            + "connection tunnelling, and may break session security if added to the whitelist.\nUnless "
                            + "you know what you're doing, "
                            + "it is HIGHLY RECOMMENDED that you DO NOT allow these IPs to be added to the whitelist.\n"
                            + "Please note that excluding an IP from this list will likely result in players connected "
                            + "through that IP to be dropped from the session.\nIf this happens, then you may have to "
                            + "check both you and your friend's Windows Firewall settings to see why they can't directly "
                            + "connect to you.\nIf this is a false-positive and you are sure an IP is a direct connection, "
                            + "you can prevent this message from appearing by manually adding them to the Custom whitelist.\n\n"
                            + "Select the potentially session security breaking IPs you wish to keep whitelisted, if any.\n"
                            "choices": c,
                        }
                        answer = prompt(options, style=style)
                        print(answer)
                        if answer is not None:
                            try:
                                for ip in answer["option"]:
                                    # Anything that has been checked will not be considered a tunnel.
                                    potential_tunnels.remove(ip)
                            except KeyError:
                                # Probably the user pressing CTRL+C to cancel the selection, meaning no 'option' key.
                                pass

                        for ip in potential_tunnels:
                            ip_set.remove(ip)

                    else:
                        print("No tunnels found!")
                    local_ip = get_private_ip()
                    ip_set.add(local_ip)
                    public_ip = get_public_ip()
                    if public_ip:
                        ip_set.add(public_ip)
                    else:
                        print_white("Failed to get Public IP, running without")

                    for ip, friend in custom_ips:
                        if friend.get("enabled"):
                            try:
                                ip_calc = IPValidator.validate_get(ip)
                                ip_set.add(ip_calc)
                            except ValidationError:
                                logger.warning("Not valid IP or URL: %s", ip)
                                print_invalid_ip(ip)
                                continue

                    for ip, friend in friends:
                        if friend.get("enabled"):
                            ip_set.add(ip)

                    os.system("cls")
                    logger.info(
                        "Starting whitelisted session with %d IPs", len(ip_set)
                    )
                    print_running_message("Whitelisted")

                    packet_filter = Whitelist(ips=ip_set)
                    try:
                        packet_filter.start()
                        while True:
                            time.sleep(10)
                    except KeyboardInterrupt:
                        packet_filter.stop()
                        logger.info("Stopping whitelisted session")
                        print_stopped_message("Whitelisted")

        elif option == "lock_session":
            print_white("LOCKED SESSION:\n")
            print(
                "This mode blocks all join requests,\n"
                "preventing new players from entering\n"
                "the session.\n\n"
                "Anyone already in the session remains,\n"
                "and this mode prevents people from entering\n"
                "the session through R* servers if someone\n"
                "is being tunnelled through a R* IP.\n\n"
                "However, if someone leaves the session\n"
                "they will not be able to get back in\n"
                "unless you end the Locked session.\n"
            )

            options = {
                "type": "list",
                "name": "option",
                "message": "Do you want to start this type of session?",
                "qmark": "@",
                "choices": [
                    {"name": "Yes, start", "value": "start"},
                    {"name": "No, go back", "value": "back"},
                ],
            }

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    os.system("cls")
                    logger.info(
                        "Session will now lock. All requests to join this session should fail."
                    )
                    print_white(
                        f'Running: "{Fore.LIGHTCYAN_EX}Locked session{Fore.LIGHTWHITE_EX}" Press "{Fore.LIGHTCYAN_EX}CTRL + C{Fore.LIGHTWHITE_EX}" to unlock session.'
                    )

                    packet_filter = Locked()
                    try:
                        packet_filter.start()
                        while True:
                            time.sleep(10)
                    except KeyboardInterrupt:
                        packet_filter.stop()
                        logger.info("Stopping whitelisted session")
                        print_stopped_message("Locked")

        elif option == "lists":
            while True:
                options = {
                    "type": "list",
                    "name": "option",
                    "qmark": "@",
                    "message": "What do you want?",
                    "choices": [
                        {"name": "Custom", "value": "custom"},
                        {"name": "Cloud", "value": "cloud"},
                        {"name": "Blacklist", "value": "blacklist"},
                        {"name": "MainMenu", "value": "return"},
                    ],
                }
                if not config.get("token"):
                    options["choices"][1]["disabled"] = "No token"
                answer = prompt(options, style=style)
                if not answer or answer["option"] == "return":
                    os.system("cls")
                    break

                elif answer["option"] == "custom":
                    os.system("cls")
                    while True:
                        options = {
                            "type": "list",
                            "name": "option",
                            "qmark": "@",
                            "message": "Custom list",
                            "choices": [
                                {"name": "Select", "value": "select"},
                                {"name": "Add", "value": "add"},
                                {"name": "List", "value": "list"},
                                {"name": "MainMenu", "value": "return"},
                            ],
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer["option"] == "return":
                            os.system("cls")
                            break

                        elif answer["option"] == "select":
                            os.system("cls")
                            if len(custom_ips) <= 0:
                                print_white("No friends")
                                continue
                            else:
                                c = [
                                    {
                                        "name": f.get("name"),
                                        "checked": True if f.get("enabled") else None,
                                    }
                                    for ip, f in custom_ips
                                ]
                                options = {
                                    "type": "checkbox",
                                    "name": "option",
                                    "qmark": "@",
                                    "message": "Select who to enable",
                                    "choices": c,
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system("cls")
                                    continue
                                for ip, item in custom_ips:
                                    item["enabled"] = (
                                        item.get("name") in answer["option"]
                                    )
                                config.save()

                        # TODO: Prevent users from accidentally adding R* / T2 IPs to the whitelist.
                        # Perhaps this could be done by updating the validator?
                        elif answer["option"] == "add":
                            os.system("cls")
                            options = [
                                {
                                    "type": "input",
                                    "name": "name",
                                    "message": "Name",
                                    "qmark": "@",
                                    "validate": NameInCustom,
                                },
                                {
                                    "type": "input",
                                    "name": "ip",
                                    "message": "IP/URL",
                                    "qmark": "@",
                                    "validate": IPInCustom,
                                },
                            ]

                            answer = prompt(options, style=style)
                            if not answer:
                                os.system("cls")
                                continue
                            try:
                                ip = IPValidator.validate_get(answer["ip"])
                                item = {"name": answer["name"], "enabled": True}
                                if ip != answer["ip"]:
                                    item["value"] = answer["ip"]
                                custom_ips.add(ip, item)
                                config.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer["option"] == "list":
                            os.system("cls")
                            while True:
                                if len(custom_ips) <= 0:
                                    print_white("No friends")
                                    break
                                else:
                                    c = [
                                        {
                                            "name": f.get("name"),
                                            "checked": True
                                            if f.get("enabled")
                                            else None,
                                        }
                                        for ip, f in custom_ips
                                    ]
                                    options = {
                                        "type": "list",
                                        "name": "name",
                                        "qmark": "@",
                                        "message": "Select who view",
                                        "choices": c,
                                    }
                                    name = prompt(options, style=style)
                                    if not name:
                                        os.system("cls")
                                        break
                                    options = {
                                        "type": "list",
                                        "name": "option",
                                        "qmark": "@",
                                        "message": "Select what to do",
                                        "choices": [
                                            {"name": "Edit", "value": "edit"},
                                            {"name": "Delete", "value": "delete"},
                                            {"name": "Back", "value": "return"},
                                        ],
                                    }
                                    name = name["name"]
                                    answer = prompt(options, style=style)
                                    if not answer or answer["option"] == "return":
                                        os.system("cls")
                                        break

                                    elif answer["option"] == "edit":
                                        while True:
                                            print(
                                                "Notice, user deleted. Press enter to go back / Save. Quit and you lose him."
                                            )
                                            ip, item = custom_ips.find(name)
                                            entry = item.get("value", ip)
                                            custom_ips.delete(ip)
                                            config.save()
                                            options = [
                                                {
                                                    "type": "input",
                                                    "name": "name",
                                                    "message": "Name",
                                                    "qmark": "@",
                                                    "validate": NameInCustom,
                                                    "default": name,
                                                },
                                                {
                                                    "type": "input",
                                                    "name": "ip",
                                                    "message": "IP/URL",
                                                    "qmark": "@",
                                                    "validate": IPInCustom,
                                                    "default": entry,
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system("cls")
                                                break
                                            try:
                                                ip = IPValidator.validate_get(
                                                    answer["ip"]
                                                )
                                                item["name"] = answer["name"]
                                                item["enabled"] = True
                                                if ip != answer["ip"]:
                                                    item["value"] = answer["ip"]
                                                custom_ips.add(ip, item)
                                                config.save()
                                                os.system("cls")
                                            except ValidationError as e:
                                                custom_ips.add(ip, item)
                                                config.save()
                                                print_white(
                                                    "Original item was restored due to error: "
                                                    + e.message
                                                )
                                            break

                                    elif answer["option"] == "delete":
                                        ip, item = custom_ips.find(name)
                                        custom_ips.delete(ip)
                                        config.save()

                elif answer["option"] == "blacklist":
                    os.system("cls")
                    while True:
                        options = {
                            "type": "list",
                            "name": "option",
                            "qmark": "@",
                            "message": "Blacklist",
                            "choices": [
                                {"name": "Select", "value": "select"},
                                {"name": "Add", "value": "add"},
                                {"name": "List", "value": "list"},
                                {"name": "MainMenu", "value": "return"},
                            ],
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer["option"] == "return":
                            os.system("cls")
                            break

                        elif answer["option"] == "select":
                            os.system("cls")
                            if len(blacklist) <= 0:
                                print_white("No ips")
                                continue
                            else:
                                c = [
                                    {
                                        "name": f.get("name"),
                                        "checked": True if f.get("enabled") else None,
                                    }
                                    for ip, f in blacklist
                                ]
                                options = {
                                    "type": "checkbox",
                                    "name": "option",
                                    "qmark": "@",
                                    "message": "Select who to enable",
                                    "choices": c,
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system("cls")
                                    continue
                                for ip, item in blacklist:
                                    item["enabled"] = (
                                        item.get("name") in answer["option"]
                                    )
                                config.save()

                        elif answer["option"] == "add":
                            os.system("cls")
                            options = [
                                {
                                    "type": "input",
                                    "name": "name",
                                    "message": "Name",
                                    "qmark": "@",
                                    "validate": NameInBlacklist,
                                },
                                {
                                    "type": "input",
                                    "name": "ip",
                                    "message": "IP/URL",
                                    "qmark": "@",
                                    "validate": IPInBlacklist,
                                },
                            ]

                            answer = prompt(options, style=style)
                            if not answer:
                                os.system("cls")
                                continue
                            try:
                                ip = IPValidator.validate_get(answer["ip"])
                                item = {"name": answer["name"], "enabled": True}
                                if ip != answer["ip"]:
                                    item["value"] = answer["ip"]
                                blacklist.add(ip, item)
                                config.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer["option"] == "list":
                            os.system("cls")
                            while True:
                                if len(blacklist) <= 0:
                                    print_white("No friends")
                                    break
                                else:
                                    c = [
                                        {
                                            "name": f.get("name"),
                                            "checked": True
                                            if f.get("enabled")
                                            else None,
                                        }
                                        for ip, f in blacklist
                                    ]
                                    options = {
                                        "type": "list",
                                        "name": "name",
                                        "qmark": "@",
                                        "message": "Select who view",
                                        "choices": c,
                                    }
                                    name = prompt(options, style=style)
                                    if not name:
                                        os.system("cls")
                                        break
                                    options = {
                                        "type": "list",
                                        "name": "option",
                                        "qmark": "@",
                                        "message": "Select what to do",
                                        "choices": [
                                            {"name": "Edit", "value": "edit"},
                                            {"name": "Delete", "value": "delete"},
                                            {"name": "Back", "value": "return"},
                                        ],
                                    }
                                    name = name["name"]
                                    answer = prompt(options, style=style)
                                    if not answer or answer["option"] == "return":
                                        os.system("cls")
                                        break

                                    elif answer["option"] == "edit":
                                        while True:
                                            print(
                                                "Notice, user deleted. Press enter to go back / Save. Quit and you lose him."
                                            )
                                            ip, item = blacklist.find(name)
                                            blacklist.delete(ip)
                                            config.save()
                                            entry = item.get("value", ip)
                                            options = [
                                                {
                                                    "type": "input",
                                                    "name": "name",
                                                    "message": "Name",
                                                    "qmark": "@",
                                                    "validate": NameInBlacklist,
                                                    "default": name,
                                                },
                                                {
                                                    "type": "input",
                                                    "name": "ip",
                                                    "message": "IP/URL",
                                                    "qmark": "@",
                                                    "validate": IPInBlacklist,
                                                    "default": entry,
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system("cls")
                                                break
                                            try:
                                                ip = IPValidator.validate_get(
                                                    answer["ip"]
                                                )
                                                item["name"] = answer["name"]
                                                item["enabled"] = True
                                                if ip != answer["ip"]:
                                                    item["value"] = answer["ip"]
                                                blacklist.add(ip, item)
                                                config.save()
                                                os.system("cls")
                                            except ValidationError as e:
                                                blacklist.add(ip, item)
                                                config.save()
                                                print_white(
                                                    "Original item was restored due to error: "
                                                    + e.message
                                                )
                                            break

                                    elif answer["option"] == "delete":
                                        ip, item = blacklist.find(name)
                                        blacklist.delete(ip)
                                        config.save()

                elif answer["option"] == "cloud":
                    os.system("cls")
                    while True:
                        options = {
                            "type": "list",
                            "name": "option",
                            "qmark": "@",
                            "message": "Custom list",
                            "choices": [
                                {"name": "Select", "value": "select"},
                                {"name": "Permission", "value": "permission"},
                                {"name": "Return", "value": "return"},
                            ],
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer["option"] == "return":
                            os.system("cls")
                            break

                        elif answer["option"] == "select":
                            os.system("cls")
                            data.update_cloud_friends()
                            if len(friends) <= 0:
                                print_white("No friends")
                                break
                            else:
                                options = {
                                    "type": "checkbox",
                                    "name": "option",
                                    "qmark": "@",
                                    "message": "Select who to enable",
                                    "choices": [
                                        {
                                            "name": f.get("name"),
                                            "value": f.get("name"),
                                            "checked": True
                                            if f.get("enabled")
                                            else None,
                                        }
                                        for ip, f in friends
                                    ],
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system("cls")
                                    break
                                for ip, f in friends:
                                    f["enabled"] = f.get("name") in answer["option"]
                                config.save()

                        elif answer["option"] == "permission":
                            os.system("cls")
                            while True:
                                token = config.get("token")
                                cloud = networkmanager.Cloud(token)
                                if not cloud.check_connection():
                                    print_white("Cloud service down")
                                    break

                                options = {
                                    "type": "list",
                                    "name": "option",
                                    "qmark": "@",
                                    "message": "Custom list",
                                    "choices": [
                                        {
                                            "name": "Revoke permission",
                                            "value": "revoke",
                                        },
                                        {
                                            "name": "Request permission",
                                            "value": "request",
                                        },
                                        {
                                            "name": "Pending requests",
                                            "value": "pending",
                                        },
                                        {"name": "Return", "value": "return"},
                                    ],
                                }
                                answer = prompt(options, style=style)
                                if not answer or answer["option"] == "return":
                                    os.system("cls")
                                    break

                                elif answer["option"] == "revoke":
                                    # My perms
                                    os.system("cls")
                                    while True:
                                        allowed_ips = cloud.get_allowed()
                                        if len(allowed_ips) <= 0:
                                            print_white("None")
                                            break
                                        options = {
                                            "type": "list",
                                            "name": "option",
                                            "qmark": "@",
                                            "message": "Who to revoke",
                                            "choices": [
                                                f.get("name") for f in allowed_ips
                                            ],
                                        }
                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system("cls")
                                            break
                                        name = answer["option"]
                                        code, msg = cloud.revoke(name)
                                        if code == 200:
                                            print_white("Revoked")
                                        else:
                                            print_white("{}".format(msg.get("error")))

                                elif answer["option"] == "request":
                                    # My friends who I don't have perms from
                                    os.system("cls")
                                    while True:
                                        friends = cloud.get_all()
                                        if len(friends) <= 0:
                                            print_white("No friends")
                                            break
                                        options = {
                                            "type": "list",
                                            "name": "option",
                                            "qmark": "@",
                                            "message": "Request from who",
                                            "choices": [
                                                f.get("name") for ip, f in friends
                                            ],
                                        }
                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system("cls")
                                            break
                                        name = answer["option"]
                                        result, msg = cloud.request(name)
                                        if result:
                                            print_white("Request sent")
                                        else:
                                            print_white("{}".format(msg))

                                elif answer["option"] == "pending":
                                    # friends who requested permission from me
                                    os.system("cls")
                                    while True:
                                        pending = cloud.get_pending()
                                        if len(pending) <= 0:
                                            print_white("None")
                                            break
                                        options = {
                                            "type": "list",
                                            "name": "option",
                                            "qmark": "@",
                                            "message": "Select user",
                                            "choices": [f.get("name") for f in pending],
                                        }
                                        answer = prompt(options, style=style)
                                        name = answer["option"]
                                        if not answer:
                                            os.system("cls")
                                            break

                                        options = {
                                            "type": "list",
                                            "name": "option",
                                            "qmark": "@",
                                            "message": "Option",
                                            "choices": [
                                                {"name": "Decline", "value": "decline"},
                                                {"name": "Accept", "value": "accept"},
                                                {"name": "Return", "value": "return"},
                                            ],
                                        }
                                        answer = prompt(options, style=style)

                                        if not answer or answer["option"] == "return":
                                            os.system("cls")
                                            break
                                        elif answer["option"] == "accept":
                                            result, msg = cloud.accept(name)
                                            if result:
                                                print_white("Accepted")
                                            else:
                                                print_white(str(msg))

                                        elif answer["option"] == "decline":
                                            result, msg = cloud.revoke(name)
                                            if result:
                                                print_white("Request declined")
                                            else:
                                                print_white(str(msg))

        elif option == "kick_by_ip":
            collector = IPCollector()
            collector.start()
            for _ in tqdm(range(10), ascii=True, desc="Collecting session"):
                time.sleep(1)
            collector.stop()
            ip_set = set(collector.ips)
            os.system("cls")
            if len(ip_set) <= 0:
                print_white("None")
                break
            options = {
                "type": "checkbox",
                "name": "option",
                "qmark": "@",
                "message": "Select IP's to kick",
                "choices": [ip for ip in ip_set],
            }
            answer = prompt(options, style=style)
            if not answer:
                os.system("cls")
                break

            ips = answer["option"]
            print_white(
                'Running: "'
                + Fore.LIGHTBLACK_EX
                + "Blacklist"
                + Fore.LIGHTWHITE_EX
                + '"'
            )
            packet_filter = Blacklist(ips=ips)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()

        elif option == "kick":
            local_ip = get_private_ip()
            ip_set = {local_ip}
            public_ip = get_public_ip()
            if public_ip:
                ip_set.add(public_ip)
            else:
                print_white("Failed to get Public IP, running without")
            for ip, friend in custom_ips:
                if friend.get("enabled"):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        ip_set.add(ip_calc)
                    except ValidationError:
                        logger.warning("Not valid IP or URL: {}".format(ip))
                        print_invalid_ip(ip)
                        continue

            for ip, friend in friends:
                if friend.get("enabled"):
                    ip_set.add(ip)
            print_white("Kicking unknowns")
            time.sleep(2)
            packet_filter = Whitelist(ips=ip_set)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == "new":
            print_white("Creating new session")
            time.sleep(2)
            packet_filter = Whitelist(ips=[])
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == "token":
            token = config.get("token")
            options = {
                "type": "input",
                "name": "token",
                "qmark": "@",
                "message": "Paste your token:",
                "validate": ValidateToken,
            }
            if token:
                options["default"] = token
            answer = prompt(options, style=style)
            if not answer:
                os.system("cls")
                continue
            config.set("token", answer["token"])
            config.save()
            os.system("cls")
            print_white(
                'New token: "'
                + Fore.LIGHTCYAN_EX
                + answer["token"]
                + Fore.LIGHTWHITE_EX
                + '"'
            )

        elif option == "discord":
            os.system("cls")
            print_white("Opening Discord URL in your default browser...")
            webbrowser.open("https://discord.gg/6FzKCh4j4v")

        elif option == "support_zip":
            os.system("cls")
            print_white(
                "NOTICE: This program will now log all udp traffic on port 6672 for 1 minute. "
                "Only run this if you are okay with that."
            )
            options = {
                "type": "confirm",
                "name": "agree",
                "qmark": "@",
                "message": "Agree?",
            }
            answer = prompt(options, style=style)
            if not answer:
                os.system("cls")
                continue
            if answer.get("agree"):
                local_list = config.get("custom_ips")
                cloud_list = config.get("friends")
                ip_set = []
                for friend in local_list:
                    if friend.get("enabled"):
                        try:
                            ip = IPValidator.validate_get(friend.get("ip"))
                            ip_set.append(ip)
                        except ValidationError:
                            continue
                for friend in cloud_list:
                    if friend.get("enabled"):
                        ip_set.append(friend.get("ip"))
                debugger = Debugger(ip_set)
                debugger.start()
                for _ in tqdm(range(60), ascii=True, desc="Collecting Requests"):
                    time.sleep(1)
                debugger.stop()
                time.sleep(1)
                print_white("Collecting data")
                token = config.get("token")
                print_white("Checking connections")
                runner = networkmanager.Cloud()
                if runner.check_connection():
                    da_status = "Online"
                else:
                    da_status = "Offline"
                if da_status and token:
                    runner = networkmanager.Cloud(token)
                    if da_status == "Online":
                        if runner.check_token():
                            has_token = "Has a valid token"
                        else:
                            has_token = "Has a invalid token"
                    else:
                        has_token = "Has token but could not check it"
                else:
                    has_token = "Does not have a token"

                datas = {
                    "token": has_token,
                    "da_status": da_status,
                    "customlist": custom_ips,
                    "cloud": friends,
                }

                print_white("Writing data")
                with open("datacheck.json", "w+") as datafile:
                    json.dump(datas, datafile, indent=2)
                print_white("Packing debug request")
                compressed = zipfile.ZipFile(
                    "debugger-{}.zip".format(time.strftime("%Y%m%d-%H%M%S")),
                    "w",
                    zipfile.ZIP_DEFLATED,
                )
                compressed.write("datacheck.json")
                try:
                    compressed.write("debugger.log")
                except FileNotFoundError:
                    pass
                os.remove("datacheck.json")
                try:
                    os.remove("debugger.log")
                except FileNotFoundError:
                    pass
                print_white("Finished")
                compressed.close()
                continue
            else:
                print_white("Declined")
                continue

        elif option == "quit":
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)


if __name__ == "__main__":
    freeze_support()

    try:
        success = False
        while not success:
            try:
                config = data.ConfigData(data.file_name)
                success = True
            except Exception as e:
                # config file could not be loaded. either file creation failed or data.json is corrupt.
                if not os.path.isfile(data.file_name):
                    # could not create config. fatal error. MB_OK is 0x0, MB_ICON_ERROR is 0x10
                    ctypes.windll.user32.MessageBoxW(
                        None,
                        f"FATAL: Guardian could not create the config file {data.file_name}.\n\n"
                        f"Press 'Ok' to close the program.",
                        "Fatal Error",
                        0x0 | 0x10,
                    )
                    raise e
                else:
                    # MB_ABORTRETRYIGNORE is 0x2, MB_ICON_ERROR is 0x10
                    choice = ctypes.windll.user32.MessageBoxW(
                        None,
                        f"Guardian could not load the config file {data.file_name}.\n\n"
                        f"The most common reason for this error is that the file is corrupt.\n\n"
                        f"Press 'Abort' to close Guardian, press 'Retry' to load the config again, "
                        f"or press 'Ignore' to \"Refresh\" Guardian by renaming the corrupt "
                        f"config file and creating a new one.",
                        "Error",
                        0x2 | 0x10,
                    )
                    # ID_ABORT = 0x3, ID_RETRY = 0x4, ID_IGNORE = 0x5
                    if choice == 0x3:
                        sys.exit(-2)
                    elif choice == 0x4:
                        pass  # we'll hit the bottom of the loop and try again
                    else:
                        separator = data.file_name.rindex(".")
                        new_name = f"{data.file_name[:separator]}_{hex(int(time.time_ns()))[2:]}{data.file_name[separator:]}"
                        os.rename(data.file_name, new_name)

        # at this point the file has been parsed and is valid
        # Any additional exceptions are explicit or programmer error
        try:
            blacklist = data.CustomList("blacklist")
            custom_ips = data.CustomList("custom_ips")
            friends = data.CustomList("friends")
        except data.MigrationRequired:
            data.migrate_to_dict()
            time.sleep(5)
            sys.exit()

        os.system("cls")
        logger.info("Init")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print_white("Please start as administrator")
            logger.info("Started without admin")
            input("Press enter to exit.")
            sys.exit()
        logger.info("Booting up")
        print_white("Booting up...")
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        ctypes.windll.kernel32.SetConsoleTitleW("Guardian {}".format(version))
        cloud = networkmanager.Cloud()
        ipsyncer = IPSyncer(None)
        print_white("Building dynamic blacklist...")
        dynamic_blacklist = set()
        try:
            dynamic_blacklist = util.DynamicBlacklist.get_dynamic_blacklist("db.json")
        except (
            util.DynamicBlacklist.ScrapeError,
            RequestException,
            json.decoder.JSONDecodeError,
            IndexError,
            ValueError,
            TypeError,
            KeyError,
            FileNotFoundError,
        ) as e:
            print_white(
                f"ERROR: Could not construct dynamic blacklist: {e}\nAuto-Whitelist and Blacklist will not work correctly."
            )
            time.sleep(3)
        print_white("Checking connections.")
        if cloud.check_connection():
            version = cloud.version()
            version = version.get("version", None) if version else None
            if version:
                if StrictVersion(version) > StrictVersion(version):
                    os.system("cls")
                    print_white("An update was found.")
                    options = {
                        "type": "confirm",
                        "message": "Open browser?",
                        "name": "option",
                        "qmark": "@",
                        "default": True,
                    }
                    answer = prompt(options, style=style)
                    if answer["option"]:
                        webbrowser.open(
                            "https://www.thedigitalarc.com/software/Guardian"
                        )
            token = config.get("token")
            if token:
                cloud.token = token
                if cloud.check_token():
                    ipsyncer.token = token
                    ipsyncer.start()
                    print_white("Starting IP syncer.")
    except Exception as e:
        crash_report(e, "Guardian crashed before reaching main()")
        raise

    while True:
        try:
            main()
        except KeyboardInterrupt:
            continue
        except Exception as e:
            crash_report(e, "Guardian crashed in main()")
            raise  # still crash the program because it's not recoverable
        finally:
            ipsyncer.stop()
