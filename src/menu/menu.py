import time
import webbrowser
from multiprocessing import Pipe

import questionary
from tqdm import tqdm

from config.configdata import ConfigData
from config.globallist import Blacklist, Whitelist
from dispatcher.context import Context
from network.sessions import (
    AbstractPacketFilter,
    BlacklistSession,
    IPCollector,
    LockedSession,
    SoloSession,
    WhitelistSession,
)
from util.constants import DISCORD_URL
from util.dynamicblacklist import get_dynamic_blacklist
from util.network import get_private_ip, get_public_ip, ip_in_cidr_block_set
from util.printer import print_invalid_ip
from validator.ip import IPValidator

UI_STYLE = questionary.Style(
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
        try:
            while True:
                answer = questionary.select(
                    "What do you want?", Prompts.MAIN_MENU, style=UI_STYLE
                ).ask()

                if callable(answer):
                    answer()

        except KeyboardInterrupt:
            return

    @staticmethod
    def confirm(prompt: list[dict[str, str]]):
        return questionary.select(
            "What do you want?",
            prompt,
            style=UI_STYLE,
        ).ask()

    @staticmethod
    def confirm_session(session_type: type[AbstractPacketFilter]):
        print(Prompts.EXPLANATIONS[session_type])
        return Menu.confirm(Prompts.CONFIRM_SESSION_OPTIONS)

    @staticmethod
    def launch_session(session_type: type[AbstractPacketFilter], *args, **kwargs):
        answer = Menu.confirm_session(session_type)
        if answer == Prompts.CONFIRM_SESSION_ANSWER_YES:
            session = session_type(*args, **kwargs)
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def launch_solo_session():
        Menu.launch_session(
            SoloSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_whitelisted_session():
        ip_set = set()
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
    def launch_blacklisted_session():
        ip_set = set()
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
    def launch_locked_session():
        Menu.launch_session(
            LockedSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_new_session():
        print(Prompts.NEW_SESSION_EXPLANATION)
        answer = Menu.confirm(Prompts.CONFIRM_SESSION_OPTIONS)
        if answer == Prompts.CONFIRM_SESSION_ANSWER_YES:
            SoloSession(Menu.context.priority, connection=Menu.child_conn)

    @staticmethod
    def launch_auto_whitelisted_session():
        print(Prompts.AUTO_WHITELISTED_EXPLANATION)
        answer = Menu.confirm(Prompts.CONFIRM_SESSION_OPTIONS)
        if answer == Prompts.CONFIRM_SESSION_ANSWER_YES:
            ip_set = Menu.collect_active_ips()
            print("Checking for potential tunnels in collected IPs...")
            potential_tunnels = {
                ip
                for ip in ip_set
                if ip_in_cidr_block_set(ip, Menu.dynamic_blacklist)
                and ip not in Menu.whitelist
            }
            if potential_tunnels:
                questionary.checkbox(
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
                    + "you can prevent this message from appearing by manually adding them to your Whitelist.\n\n"
                    + "Select the potentially session security breaking IPs you wish to keep whitelisted, if any.\n",
                    choices=potential_tunnels,
                    style=UI_STYLE,
                ).ask()
                for ip in answer:
                    potential_tunnels.remove(ip)
                for ip in potential_tunnels:
                    ip_set.remove(ip)
            WhitelistSession(ip_set, Menu.context.priority, connection=Menu.child_conn)

    @staticmethod
    def kick_unknowns():
        print(Prompts.KICK_UNKNOWNS_EXPLANATION)
        answer = Menu.confirm(Prompts.CONFIRM_SESSION_OPTIONS)
        if answer == Prompts.CONFIRM_SESSION_ANSWER_YES:
            ip_set = set()
            for ip, name in Menu.whitelist:
                try:
                    ip_calc = IPValidator.validate_get(ip)
                    ip_set.add(ip_calc)
                except questionary.ValidationError:
                    print_invalid_ip(ip)
            WhitelistSession(ip_set, Menu.context.priority, connection=Menu.child_conn)
            # TODO: Terminate after 10 seconds

    @staticmethod
    def kick_by_ip():
        print(Prompts.KICK_BY_IP_EXPLANATION)
        answer = Menu.confirm(Prompts.CONFIRM_SESSION_OPTIONS)
        if answer == Prompts.CONFIRM_SESSION_ANSWER_YES:
            ip_set = Menu.collect_active_ips()
            choices = questionary.checkbox(
                "Select IPs to kick", ip_set, style=UI_STYLE
            ).ask()
            for ip in choices:
                ip_set.remove(ip)
            WhitelistSession(ip_set, Menu.context.priority, connection=Menu.child_conn)
            # TODO: Terminate after 10 seconds

    @staticmethod
    def open_discord():
        print("Opening Discord URL...")
        webbrowser.open(DISCORD_URL)

    @staticmethod
    def quit():
        raise KeyboardInterrupt

    @staticmethod
    def collect_active_ips(duration_seconds: int = 60) -> set[str]:
        collector = IPCollector(Menu.context.priority, packet_count_min_threshold=15)
        collector.start()
        for _ in tqdm(
            range(duration_seconds), ascii=True, desc="Collecting session IPs"
        ):
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
        {"name": "Discord", "value": Menu.open_discord},
        {"name": "Quit", "value": Menu.quit},
    ]

    CONFIRM_SESSION_ANSWER_YES = "y"
    CONFIRM_SESSION_ANSWER_NO = "n"

    CONFIRM_SESSION_OPTIONS = [
        {"name": "Yes, start", "value": CONFIRM_SESSION_ANSWER_YES},
        {"name": "No, go back", "value": CONFIRM_SESSION_ANSWER_NO},
    ]

    # LISTS_MENU = [
    #     {"name": "Whitelist", "value": Menu.Settings.Lists.Whitelist.main},
    #     {"name": "Blacklist", "value": Menu.Settings.Lists.Blacklist.main},
    #     {"name": "Delegate Mode", "value": Menu.Settings.Lists.DelegateMode.main},
    #     {"name": "Go back", "value": "return"},
    # ]

    # WHITELIST_MENU = [
    #     {"name": "Toggle", "value": Menu.Settings.Lists.Whitelist.toggle},
    #     {"name": "Add", "value": Menu.Settings.Lists.Whitelist.add},
    #     {"name": "Edit", "value": Menu.Settings.Lists.Whitelist.edit},
    #     {"name": "Go back", "value": "return"},
    # ]

    # BLACKLIST_MENU = [
    #     {"name": "Toggle", "value": Menu.Settings.Lists.Blacklist.toggle},
    #     {"name": "Add", "value": Menu.Settings.Lists.Blacklist.add},
    #     {"name": "Edit", "value": Menu.Settings.Lists.Blacklist.edit},
    #     {"name": "Go back", "value": "return"},
    # ]

    EXPLANATIONS: dict[type[AbstractPacketFilter], str] = {
        SoloSession: (
            "No one can connect to your game session,\n"
            "but critical R* and SocialClub activity\n"
            "will still get through.\n\n"
            "If you are in a session with any other player,\n"
            "they will lose connection to you.\n"
        ),
        WhitelistSession: (
            "Only IP addresses in your Whitelist\n"
            "will be allowed to connect to you.\n\n"
            "If you are the host of a session,\n"
            "anyone not on your Whitelist will\n"
            "likely lose connection to the session.\n\n"
            "If you are not the host (and any player\n"
            "in the session is not on your Whitelist)\n"
            "you will lose connection to everyone else.\n"
        ),
        BlacklistSession: (
            "IP addresses in your Blacklist\n"
            "will not be allowed to connect to you.\n\n"
            "If a connection is routed through R* servers,\n"
            "that connection will also be blocked\n"
            "as a security measure.\n\n"
            "This mode is NOT RECOMMENDED as GTA Online\n"
            "has custom routing if only a handful of\n"
            "IP addresses are blocked.\n"
        ),
        LockedSession: (
            "This mode blocks all join requests,\n"
            "preventing new players from entering\n"
            "the session.\n\n"
            "Anyone already in the session remains.\n"
            "This mode prevents people from entering\n"
            "the session through R* servers if someone\n"
            "is being tunnelled through a R* IP.\n\n"
            "However, if a player leaves the session\n"
            "they will not be able to join again.\n"
        ),
    }

    AUTO_WHITELISTED_EXPLANATION = (
        "Similar to Whitelisted session, except\n"
        "everybody currently in the session is\n"
        "temporarily added to your whitelist,\n"
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

    KICK_UNKNOWNS_EXPLANATION = (
        "Attempts to kick any IP that is not\n"
        "on your Whitelist out of the session.\n\n"
        "Keeping your sessions safe in this manner\n"
        "is NOT RECOMMENDED, as clients may try to\n"
        "route unknown player traffic through IPs\n"
        "that are on your Custom list.\n"
    )

    NEW_SESSION_EXPLANATION = (
        "Splits you from the current session so you are alone.\n"
        "Being the only player in a session ensures that\n"
        "you are the session Host."
    )

    KICK_BY_IP_EXPLANATION = (
        "Captures IPs in your session, then\n"
        "allows you to select an IP to kick.\n\n"
        "This mode is NOT RECOMMENDED for the\n"
        "same reason that kicking unknowns may\n"
        "not work."
    )
