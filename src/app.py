import ctypes
import json
import logging
import os
import sys
import time
import traceback
import webbrowser
import zipfile
from multiprocessing import freeze_support
from typing import Optional

import pydivert
import requests
from colorama import Fore
from prompt_toolkit.styles import Style
from questionary import ValidationError, prompt
from tqdm import tqdm

from config.configdata import ConfigData
from config.globallist import Blacklist, Whitelist
from dispatcher.context import Context
from network.iptag import IPTag
from network.sessions import (
    AbstractPacketFilter,
    BlacklistSession,
    DebugSession,
    IPCollector,
    LockedSession,
    SoloSession,
    WhitelistSession,
)
from util.dynamicblacklist import DynamicBlacklist, ScrapeError
from util.network import get_private_ip, get_public_ip, ip_in_cidr_block_set
from util.printer import (
    print_invalid_ip,
    print_running_message,
    print_stopped_message,
    print_white,
)
from validator.ip import IPInBlacklist, IPInWhitelist, IPValidator
from validator.name import NameInBlacklist, NameInWhitelist

__version__ = "3.3.1"

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


def crash_report(
    exception: Exception,
    additional: Optional[str] = None,
    filename: Optional[str] = None,
) -> None:
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


def menu():
    print_white("Building dynamic blacklist...")
    try:
        dynamic_blacklist = DynamicBlacklist.get_dynamic_blacklist()
    except (
        ScrapeError,
        requests.RequestException,
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
        dynamic_blacklist = set()
    context = Context()

    while True:
        dynamic_blacklist_checker = (
            "Experimental" if len(dynamic_blacklist) > 0 else "Not working"
        )
        options = [
            {
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
                    {"name": "Discord", "value": "discord"},
                    {"name": "Support zip", "value": "support_zip"},
                    {"name": "Quit", "value": "quit"},
                ],
            }
        ]
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

        packet_filter: AbstractPacketFilter
        if option == "solo":
            print_white("SOLO SESSION:\n")
            print(
                "No one can connect to your game session,\n"
                "but critical R* and SocialClub activity\n"
                "will still get through.\n\n"
                "If you are in a session with any other player,\n"
                "they will lose connection to you.\n"
            )

            options = [
                {
                    "type": "list",
                    "name": "option",
                    "message": "Do you want to start this type of session?",
                    "qmark": "@",
                    "choices": [
                        {"name": "Yes, start", "value": "start"},
                        {"name": "No, go back", "value": "back"},
                    ],
                }
            ]

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

                    packet_filter = SoloSession(context.priority)
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

            options = [
                {
                    "type": "list",
                    "name": "option",
                    "message": "Do you want to start this type of session?",
                    "qmark": "@",
                    "choices": [
                        {"name": "Yes, start", "value": "start"},
                        {"name": "No, go back", "value": "back"},
                    ],
                }
            ]

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
                    ip_tags = [IPTag(local_ip, "LOCAL IP")]
                    public_ip = get_public_ip()
                    if public_ip:
                        ip_set.add(public_ip)
                        ip_tags.append(IPTag(public_ip, "PUBLIC IP"))
                    else:
                        print_white("Failed to get Public IP, running without")

                    for ip, name in whitelist:
                        try:
                            ip_calc = IPValidator.validate_get(ip)
                            ip_set.add(ip_calc)
                            ip_tags.append(IPTag(ip_calc, f"{name} [WHITELIST]"))
                        except ValidationError:
                            logger.warning("Invalid IP: %s", ip)
                            print_invalid_ip(ip)
                            continue

                    logger.info("Starting whitelisted session with %d IPs", len(ip_set))
                    print_running_message("Whitelisted")

                    # # Exposes session information, diagnostics and behaviour.
                    # manager = Manager()
                    # connection_stats = manager.list()
                    # session_info = sessioninfo.SessionInfo(manager.dict(), connection_stats, manager.Queue(), ip_tags)

                    # Set up packet_filter outside the try-catch so it can be safely referenced inside KeyboardInterrupt.
                    packet_filter = WhitelistSession(ip_set, context.priority)

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

                            # print(session_info)
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

            options = [
                {
                    "type": "list",
                    "name": "option",
                    "message": "Do you want to start this type of session?",
                    "qmark": "@",
                    "choices": [
                        {"name": "Yes, start", "value": "start"},
                        {"name": "No, go back", "value": "back"},
                    ],
                }
            ]

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

                    ip_set = set()
                    for ip in blacklist.ips:
                        try:
                            ip = IPValidator.validate_get(ip)
                            ip_set.add(ip)
                        except ValidationError:
                            logger.warning("Invalid IP: %s", ip)
                            print_invalid_ip(ip)
                            continue
                    logger.info("Starting blacklisted session with %d IPs", len(ip_set))
                    print_running_message("Blacklist")

                    packet_filter = BlacklistSession(
                        ip_set,
                        context.priority,
                        blocks=dynamic_blacklist,
                        known_allowed=allowed_ips,
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

            options = [
                {
                    "type": "list",
                    "name": "option",
                    "message": "Do you want to start this type of session?",
                    "qmark": "@",
                    "choices": [
                        {"name": "Yes, start", "value": "start"},
                        {"name": "No, go back", "value": "back"},
                    ],
                }
            ]

            answer = prompt(
                options,
                style=style,
            )
            if answer:
                os.system("cls")
                option = answer["option"]

                if option == "start":

                    logger.info("Starting auto whitelisted session")
                    collector = IPCollector(
                        context.priority, packet_count_min_threshold=15
                    )
                    logger.info("Starting to collect IPs")
                    collector.start()
                    for _ in tqdm(range(10), ascii=True, desc="Collecting session"):
                        time.sleep(1)
                    collector.stop()
                    ip_set = set(collector.ips)
                    logger.info("Collected %d IPs", len(ip_set))
                    print("Checking for potential tunnels in collected IPs...\n")
                    potential_tunnels = set()
                    for ip in ip_set:
                        if ip_in_cidr_block_set(ip, dynamic_blacklist):
                            # Ignore if user has this IP in custom whitelist.
                            if ip not in whitelist:
                                potential_tunnels.add(ip)
                    if len(potential_tunnels) > 0:
                        c = [{"name": ip, "checked": False} for ip in potential_tunnels]
                        options = [
                            {
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
                        ]
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

                    for ip, name in whitelist:
                        try:
                            ip_calc = IPValidator.validate_get(ip)
                            ip_set.add(ip_calc)
                        except ValidationError:
                            logger.warning("Invalid IP: %s", ip)
                            print_invalid_ip(ip)
                            continue

                    os.system("cls")
                    logger.info("Starting whitelisted session with %d IPs", len(ip_set))
                    print_running_message("Whitelisted")

                    packet_filter = WhitelistSession(ip_set, context.priority)
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

            options = [
                {
                    "type": "list",
                    "name": "option",
                    "message": "Do you want to start this type of session?",
                    "qmark": "@",
                    "choices": [
                        {"name": "Yes, start", "value": "start"},
                        {"name": "No, go back", "value": "back"},
                    ],
                }
            ]

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

                    packet_filter = LockedSession(context.priority)
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
                options = [
                    {
                        "type": "list",
                        "name": "option",
                        "qmark": "@",
                        "message": "What do you want?",
                        "choices": [
                            {"name": "Whitelist", "value": "whitelist"},
                            {"name": "Blacklist", "value": "blacklist"},
                            {"name": "MainMenu", "value": "return"},
                        ],
                    }
                ]
                answer = prompt(options, style=style)
                if not answer or answer["option"] == "return":
                    os.system("cls")
                    break

                elif answer["option"] == "whitelist":
                    os.system("cls")
                    while True:
                        options = [
                            {
                                "type": "list",
                                "name": "option",
                                "qmark": "@",
                                "message": "Whitelist",
                                "choices": [
                                    {"name": "Select", "value": "select"},
                                    {"name": "Add", "value": "add"},
                                    {"name": "List", "value": "list"},
                                    {"name": "MainMenu", "value": "return"},
                                ],
                            }
                        ]
                        answer = prompt(options, style=style)

                        if not answer or answer["option"] == "return":
                            os.system("cls")
                            break

                        elif answer["option"] == "add":
                            os.system("cls")
                            options = [
                                {
                                    "type": "input",
                                    "name": "name",
                                    "message": "Name",
                                    "qmark": "@",
                                    "validate": NameInWhitelist,
                                },
                                {
                                    "type": "input",
                                    "name": "ip",
                                    "message": "IP address",
                                    "qmark": "@",
                                    "validate": IPInWhitelist,
                                },
                            ]

                            answer = prompt(options, style=style)
                            if not answer:
                                os.system("cls")
                                continue
                            try:
                                ip = IPValidator.validate_get(answer["ip"])
                                whitelist.add(ip, answer["name"])
                                whitelist.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer["option"] == "list":
                            os.system("cls")
                            while True:
                                if len(whitelist) <= 0:
                                    print_white("No whitelist ips")
                                    break
                                c = [{"name": name} for name in whitelist.names]
                                options = [
                                    {
                                        "type": "list",
                                        "name": "name",
                                        "qmark": "@",
                                        "message": "Select who to view",
                                        "choices": c,
                                    }
                                ]
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system("cls")
                                    break
                                name = answer["name"]
                                options = [
                                    {
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
                                ]
                                answer = prompt(options, style=style)
                                if not answer or answer["option"] == "return":
                                    os.system("cls")
                                    break

                                elif answer["option"] == "edit":
                                    while True:
                                        ip = whitelist.find(name)
                                        options = [
                                            {
                                                "type": "input",
                                                "name": "name",
                                                "message": "Name",
                                                "qmark": "@",
                                                "default": name,
                                            },
                                            {
                                                "type": "input",
                                                "name": "ip",
                                                "message": "IP address",
                                                "qmark": "@",
                                                "validate": NameInWhitelist,
                                                "default": ip,
                                            },
                                        ]

                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system("cls")
                                            break
                                        try:
                                            new_ip = IPValidator.validate_get(
                                                answer["ip"]
                                            )
                                            whitelist.remove(ip)
                                            whitelist.add(new_ip, answer["name"])
                                            os.system("cls")
                                        except ValidationError:
                                            print_white("Invalid IP, please try again.")
                                            continue
                                        whitelist.save()
                                        break

                                elif answer["option"] == "delete":
                                    ip = whitelist.find(name)
                                    whitelist.remove(ip)
                                    whitelist.save()

                elif answer["option"] == "blacklist":
                    os.system("cls")
                    while True:
                        options = [
                            {
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
                        ]
                        answer = prompt(options, style=style)

                        if not answer or answer["option"] == "return":
                            os.system("cls")
                            break

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
                                    "message": "IP address",
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
                                blacklist.add(ip, answer["name"])
                                blacklist.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer["option"] == "list":
                            os.system("cls")
                            while True:
                                if len(blacklist) <= 0:
                                    print_white("No blacklist ips")
                                    break
                                c = [{"name": name} for name in blacklist.names]
                                options = [
                                    {
                                        "type": "list",
                                        "name": "name",
                                        "qmark": "@",
                                        "message": "Select who to view",
                                        "choices": c,
                                    }
                                ]
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system("cls")
                                    break
                                name = answer["name"]
                                options = [
                                    {
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
                                ]
                                answer = prompt(options, style=style)
                                if not answer or answer["option"] == "return":
                                    os.system("cls")
                                    break

                                elif answer["option"] == "edit":
                                    while True:
                                        ip = blacklist.find(name)
                                        options = [
                                            {
                                                "type": "input",
                                                "name": "name",
                                                "message": "Name",
                                                "qmark": "@",
                                                "default": name,
                                            },
                                            {
                                                "type": "input",
                                                "name": "ip",
                                                "message": "IP address",
                                                "qmark": "@",
                                                "validate": NameInBlacklist,
                                                "default": ip,
                                            },
                                        ]

                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system("cls")
                                            break
                                        try:
                                            new_ip = IPValidator.validate_get(
                                                answer["ip"]
                                            )
                                            blacklist.remove(ip)
                                            blacklist.add(new_ip, answer["name"])
                                            os.system("cls")
                                        except ValidationError:
                                            print_white("Invalid IP, please try again.")
                                            continue
                                        blacklist.save()
                                        break

                                elif answer["option"] == "delete":
                                    ip = blacklist.find(name)
                                    blacklist.remove(ip)
                                    blacklist.save()

        elif option == "kick_by_ip":
            collector = IPCollector(context.priority)
            collector.start()
            for _ in tqdm(range(10), ascii=True, desc="Collecting session"):
                time.sleep(1)
            collector.stop()
            ip_set = set(collector.ips)
            os.system("cls")
            if len(ip_set) <= 0:
                print_white("None")
                break
            options = [
                {
                    "type": "checkbox",
                    "name": "option",
                    "qmark": "@",
                    "message": "Select IPs to kick",
                    "choices": [ip for ip in ip_set],
                }
            ]
            answer = prompt(options, style=style)
            if not answer:
                os.system("cls")
                break

            ips = answer["option"]
            print_white(f'Running: "{Fore.LIGHTBLACK_EX}Blacklist{Fore.LIGHTWHITE_EX}"')
            packet_filter = BlacklistSession(ips, context.priority)
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

            # ADD WHITELISTS HERE AS WELL

            print_white("Kicking unknowns")
            packet_filter = WhitelistSession(ip_set, context.priority)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == "new":
            print_white("Creating new session")
            packet_filter = SoloSession(context.priority)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == "discord":
            os.system("cls")
            print_white("Opening Discord URL in your default browser...")
            webbrowser.open("https://discord.gg/6FzKCh4j4v")

        elif option == "support_zip":
            os.system("cls")
            print_white(
                "NOTICE: This program will now log all udp traffic on port 6672 for 1 minute.\n"
                "This will also include your configuration file (data.json), and any IP addresses inside.\n"
                "Only run this if you are okay with that."
            )
            options = [
                {
                    "type": "confirm",
                    "name": "agree",
                    "qmark": "@",
                    "message": "Agree?",
                }
            ]
            answer = prompt(options, style=style)
            if not answer:
                os.system("cls")
                continue
            if answer.get("agree"):
                debugger = DebugSession(whitelist.ips)
                debugger.start()
                for _ in tqdm(range(60), ascii=True, desc="Collecting Requests"):
                    time.sleep(1)
                debugger.stop()

                print_white("Packing debug request")
                with zipfile.ZipFile(
                    f"debugger-{time.strftime('%Y%m%d-%H%M%S')}.zip",
                    "w",
                    zipfile.ZIP_DEFLATED,
                ) as compressed:
                    compressed.write("debugger.log")
                    compressed.write("data.json")
                    compressed.write("db.json")
                print_white("Finished")
            else:
                print_white("Declined")

        elif option == "quit":
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)


if __name__ == "__main__":
    freeze_support()

    try:
        # Initialise singleton objects for thread-safety
        config = ConfigData()
        blacklist = Blacklist()
        whitelist = Whitelist()

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
        ctypes.windll.kernel32.SetConsoleTitleW(f"Guardian {__version__}")
    except Exception as e:
        crash_report(e, "Guardian crashed before reaching main()")
        raise

    try:
        menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        crash_report(e, "Guardian crashed in main()")
        raise
