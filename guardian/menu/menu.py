from __future__ import annotations

import logging
import time
import webbrowser
from enum import Enum
from multiprocessing import Pipe
from typing import Any, cast

import questionary
from tqdm import trange

from config.configdata import ConfigData
from config.globallist import Blacklist, Whitelist
from dispatcher.context import Context
from menu.lists import Lists
from network.sessions import (
    AbstractPacketFilter,
    BlacklistSession,
    IPCollector,
    LockedSession,
    SoloSession,
    WhitelistSession,
)
from util.constants import DISCORD_URL, UI_STYLE
from util.dynamicblacklist import get_dynamic_blacklist
from util.network import get_private_ip, get_public_ip, ip_in_cidr_block_set
from util.printer import pretty_print, print_invalid_ip
from validator.ip import IPValidator

debug_logger = logging.getLogger("debugger")

PRIVATE_IP = get_private_ip()
PUBLIC_IP = get_public_ip()


class Menu:
    parent_conn, child_conn = Pipe()
    context = Context(parent_conn)
    config = ConfigData()
    blacklist = Blacklist()
    whitelist = Whitelist()
    dynamic_blacklist = get_dynamic_blacklist()

    @staticmethod
    def main_menu() -> None:
        while True:
            try:
                answer = questionary.select(
                    "What do you want?", Prompts.MAIN_MENU, style=UI_STYLE
                ).ask()

                if callable(answer):
                    answer()
            except KeyboardInterrupt:
                return

    @staticmethod
    def confirm_session(
        session_type: type[AbstractPacketFilter] | str,
    ) -> Prompts.CONFIRM_SESSION_ANSWER:
        pretty_print(Prompts.EXPLANATIONS[session_type])
        session_type = (
            session_type if isinstance(session_type, str) else session_type.__name__
        )
        return cast(
            Prompts.CONFIRM_SESSION_ANSWER,
            questionary.select(
                f"Session type: {session_type}, are you sure?",
                Prompts.CONFIRM_SESSION_OPTIONS,
                style=UI_STYLE,
            ).ask(),
        )

    @staticmethod
    def launch_session(
        session_type: type[AbstractPacketFilter], *args: Any, **kwargs: Any
    ) -> None:
        answer = Menu.confirm_session(session_type)
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            session = session_type(*args, **kwargs)
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def launch_solo_session() -> None:
        Menu.launch_session(
            SoloSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_whitelisted_session() -> None:
        ip_set = set()
        debug_logger.debug("Validating whitelisted IPs")
        for ip, name in Menu.whitelist:
            try:
                ip_calc = IPValidator.validate_get(ip)
                ip_set.add(ip_calc)
            except questionary.ValidationError:
                print_invalid_ip(ip)
        Menu.launch_session(
            WhitelistSession,
            ips=ip_set,
            priority=Menu.context.priority,
            connection=Menu.child_conn,
        )

    @staticmethod
    def launch_blacklisted_session() -> None:
        ip_set = set()
        debug_logger.debug("Validating blacklisted IPs")
        for ip, name in Menu.blacklist:
            try:
                ip_calc = IPValidator.validate_get(ip)
                ip_set.add(ip_calc)
            except questionary.ValidationError:
                print_invalid_ip(ip)
        Menu.launch_session(
            BlacklistSession,
            ips=ip_set,
            priority=Menu.context.priority,
            connection=Menu.child_conn,
            blocks=Menu.dynamic_blacklist,
            known_allowed={PRIVATE_IP, PUBLIC_IP},
        )

    @staticmethod
    def launch_locked_session() -> None:
        Menu.launch_session(
            LockedSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_new_session() -> None:
        answer = Menu.confirm_session("New Session")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            session = SoloSession(Menu.context.priority, connection=Menu.child_conn)
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def launch_auto_whitelisted_session() -> None:
        answer = Menu.confirm_session("Auto-Whitelisted")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            print("Collecting active IPs...")
            ip_set = Menu.collect_active_ips()
            print("Checking for potential tunnels in collected IPs...")
            potential_tunnels = {
                ip
                for ip in ip_set
                if ip_in_cidr_block_set(ip, Menu.dynamic_blacklist)
                and ip not in Menu.whitelist
            }
            if potential_tunnels:
                ip_answer = questionary.checkbox(
                    f"WARNING! Guardian has detected {len(potential_tunnels)} IP"
                    f"{'' if len(potential_tunnels) == 1 else 's'} in your current session that "
                    "may be used for connection tunnelling, and may break session security if added "
                    "to the whitelist.\nUnless you know what you're doing, it is HIGHLY RECOMMENDED "
                    "that you DO NOT allow these IPs to be added to the whitelist.\nPlease note that "
                    "excluding an IP from this list will likely result in players connected through "
                    "that IP to be dropped from the session.\nIf this happens, then you may have to "
                    "check both you and your friend's Windows Firewall settings to see why they can't "
                    "directly connect to you.\nIf this is a false-positive and you are sure an IP is a "
                    "direct connection, you can prevent this message from appearing by manually adding "
                    "them to your Whitelist.\n\nSelect the potentially session-security-breaking IPs "
                    "you wish to keep whitelisted, if any.",
                    choices=list(potential_tunnels),
                    style=UI_STYLE,
                ).ask()
                for ip in ip_answer:
                    potential_tunnels.remove(ip)
                for ip in potential_tunnels:
                    ip_set.remove(ip)
            else:
                print("No potential tunnels identified")
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def kick_unknowns() -> None:
        answer = Menu.confirm_session("Kick Unknowns")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            ip_set = set()
            for ip, name in Menu.whitelist:
                try:
                    ip_calc = IPValidator.validate_get(ip)
                    ip_set.add(ip_calc)
                except questionary.ValidationError:
                    print_invalid_ip(ip)
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()
            for _ in trange(10, ascii=True, desc="Kicking unknowns..."):
                time.sleep(1)
            Menu.context.kill_latest_filter()

    @staticmethod
    def kick_by_ip() -> None:
        answer = Menu.confirm_session("Kick by IP")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            ip_set = Menu.collect_active_ips()
            choices = questionary.checkbox(
                "Select IPs to kick", list(ip_set), style=UI_STYLE
            ).ask()
            for ip in choices:
                ip_set.remove(ip)
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()
            for _ in trange(10, ascii=True, desc="Kicking unknowns..."):
                time.sleep(1)
            Menu.context.kill_latest_filter()

    @staticmethod
    def open_discord() -> None:
        print("Opening Discord URL...")
        webbrowser.open(DISCORD_URL)

    @staticmethod
    def quit() -> None:
        raise KeyboardInterrupt

    @staticmethod
    def collect_active_ips(duration_seconds: int = 60) -> set[str]:
        collector = IPCollector(Menu.context.priority, packet_count_min_threshold=15)
        collector.start()
        for _ in trange(duration_seconds, ascii=True, desc="Collecting session IPs"):
            time.sleep(1)
        collector.stop()
        return set(collector.ips)


class Prompts:
    MAIN_MENU = [
        {"name": "Solo Session", "value": Menu.launch_solo_session},
        {"name": "Whitelisted Session", "value": Menu.launch_whitelisted_session},
        {"name": "Blacklisted Session", "value": Menu.launch_blacklisted_session},
        {
            "name": "Auto Whitelisted Session",
            "value": Menu.launch_auto_whitelisted_session,
        },
        {"name": "Locked Session", "value": Menu.launch_locked_session},
        {"name": "Kick unknowns", "value": Menu.kick_unknowns},
        {
            "name": "Empty Session (force Session Host)",
            "value": Menu.launch_new_session,
        },
        {"name": "Kick by IP", "value": Menu.kick_by_ip},
        {"name": "Edit lists", "value": Lists.choose_list},
        {"name": "Discord", "value": Menu.open_discord},
        {"name": "Quit", "value": Menu.quit},
    ]

    class CONFIRM_SESSION_ANSWER(Enum):
        YES = "y"
        NO = "n"

    CONFIRM_SESSION_OPTIONS = [
        {"name": "Yes, start", "value": CONFIRM_SESSION_ANSWER.YES},
        {"name": "No, go back", "value": CONFIRM_SESSION_ANSWER.NO},
    ]

    EXPLANATIONS = {
        SoloSession: (
            "No one can connect to your game session, but critical R* and SocialClub activity "
            "will still go through.\nIf you are in a session with any other players, they will "
            "lose connection to you."
        ),
        WhitelistSession: (
            "Only IP addresses in your Whitelist will be allowed to connect to you.\nIf you are "
            "the host of a session, anyone not in your Whitelist will likely lose connection to "
            "the session.\nIf you are not the host (and any player in the session is not in your "
            "Whitelist), you will lose connection to everyone else."
        ),
        BlacklistSession: (
            "IP addresses in your Blacklist will not be allowed to connect to you.\nIf a "
            "connection is routed through R* servers, that connection will also be blocked as a "
            "security measure.\nThis mode is NOT RECOMMENDED as GTA Online has custom routing if "
            "only a handful of IP addresses are blocked."
        ),
        LockedSession: (
            "This mode blocks all join requests, preventing new players from entering the "
            "session.\nAnyone already in the session will not be kicked out. This mode prevents "
            "people from entering the session through R* servers if someone is being tunnelled "
            "through a R* IP.\nHowever, if a player leaves the session, they will not be able to "
            "join again."
        ),
        "Auto-Whitelisted": (
            "Similar to Whitelisted session, except everybody currently in the session is "
            "temporarily added to your whitelist, which prevents them from being kicked.\nAny "
            "automatically collected IPs will be lost once the session ends.\nIf Guardian detects "
            "that a player in your session is being routed through R* servers, you will be warned "
            "and prompted whether you wish to add this IP to the temporary whitelist.\nIf you do "
            "decide to allow these IPs, your session may not properly protected."
        ),
        "Kick Unknowns": (
            "Attempts to kick any IP that is not on your Whitelist out of the session.\nKeeping "
            "your sessions safe in this manner is NOT RECOMMENDED, as clients may try to route "
            "unknown player traffic through IPs that are on your Whitelist."
        ),
        "New Session": (
            "Splits you from the current session so you are alone. Being the only player in a "
            "session ensures that you are the session Host."
        ),
        "Kick by IP": (
            "Captures IPs in your session, then allows you to choose which IPs to kick.\nThis "
            "mode is NOT RECOMMENDED for the same reason that kicking unknowns may not work."
        ),
    }
