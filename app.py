from __future__ import print_function, unicode_literals
import random
import string
from questionary import Validator, ValidationError, prompt
from prompt_toolkit.styles import Style
import os
import ctypes
from colorama import Fore
from network.blocker import *
import pydivert
import sys
from multiprocessing import freeze_support, Manager
import ipaddress
from network import networkmanager, sessioninfo
from distutils.version import StrictVersion
import webbrowser
import socket
from tqdm import tqdm
import zipfile
import json
import time
import logging
import util.DynamicBlacklist    # new Azure-blocking functionality
from requests import RequestException
from pathlib import Path        # save local azure file copy
from util.WorkingDirectoryFix import wd_fix  # workaround for python's working directory jank

wd_fix()    # Fix working directory before doing literally anything else

logger = logging.getLogger('guardian')
logger.propagate = False
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(filename='history.log')
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

LF_FACESIZE = 32
STD_OUTPUT_HANDLE = -11

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")
domain = re.compile(r"^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[\[a-z0-9]+)?)+)*$")

version = '3.1.0a11'

style = Style([
    ('qmark', 'fg:#00FFFF bold'),  # token in front of the question
    ('question', 'bold'),  # question text
    ('answer', 'fg:#00FFFF bold'),  # submitted answer text behind the question
    ('pointer', 'fg:#00FFFF bold'),  # pointer used in select and checkbox prompts
    ('selected', 'fg:#FFFFFF bold'),  # style for a selected item of a checkbox
    ('separator', 'fg:#00FFFF'),  # separator in lists
    ('instruction', '')  # user instructions for select, rawselect, checkbox
])


def print_white(msg):
    print(Fore.LIGHTWHITE_EX + msg + Fore.RESET)


def get_public_ip():
    public_ip = networkmanager.Cloud().get_ip()
    if public_ip:
        logger.info('Got a public IP')
        return public_ip
    else:
        logger.warning('Failed to get public IP')
        return False


def get_private_ip():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(("8.8.8.8", 80))
    local_ip = soc.getsockname()[0]
    soc.close()
    return local_ip


class NameInCustom(Validator):
    def validate(self, document):
        global custom_ips
        if custom_ips.has(document.text):
            raise ValidationError(
                message='Name already in list',
                cursor_position=len(document.text))  # Move cursor to end


class NameInBlacklist(Validator):
    def validate(self, document):
        global blacklist
        if blacklist.has(document.text):
            raise ValidationError(
                message='Name already in list',
                cursor_position=len(document.text))  # Move cursor to end


class IPValidator(Validator):
    def validate(self, document):
        error = ValidationError(message='Not a valid IP or URL',
                                cursor_position=len(document.text))  # Move cursor to end
        try:
            ip = document.text
            if ipv4.match(ip):
                ipaddress.IPv4Address(ip)
            elif not domain.match(ip):
                raise error
        except (ipaddress.AddressValueError, socket.gaierror):
            raise error

    # TODO: Add an extra validator to check if an IP could be used by R* services (i.e. it's part of Microsoft Azure)

    @staticmethod
    def validate_get(text):
        error = ValidationError(message='Not a valid IP or URL',
                                cursor_position=len(text))  # Move cursor to end
        try:
            ip = text
            if ipv4.match(ip):
                ipaddress.IPv4Address(ip)
            elif domain.match(ip):
                ip = socket.gethostbyname(text)
                ipaddress.IPv4Address(ip)
            else:
                raise error
            return ip
        except ipaddress.AddressValueError:
            raise error
        except socket.gaierror:
            raise ValidationError(message='URL {} can\'t be resolved to IP.'.format(text),
                                  cursor_position=len(text))  # Move cursor to end


class IPInCustom(IPValidator):
    def validate(self, document):
        super().validate(document)
        global custom_ips
        if document.text in custom_ips or custom_ips.has(document.text, 'value'):
            raise ValidationError(
                message='IP already in list',
                cursor_position=len(document.text)
            )  # Move cursor to end


class IPInBlacklist(Validator):
    def validate(self, document):
        super().validate(document)
        global blacklist
        if document.text in blacklist or blacklist.has(document.text, 'value'):
            raise ValidationError(
                message='IP already in list',
                cursor_position=len(document.text)
            )  # Move cursor to end


class ValidateToken(Validator):
    def validate(self, document):
        conn = networkmanager.Cloud(document.text)
        if not conn.check_connection():
            raise ValidationError(
                message='DigitalArc is unavailable, unable to check token.',
                cursor_position=len(document.text))  # Move cursor to end

        if not conn.check_token():
            raise ValidationError(
                message='Token invalid',
                cursor_position=len(document.text))  # Move cursor to end


def main():
    global cloud, config, custom_ips, blacklist, friends, dynamic_blacklist
    while True:
        token = config.get('token')
        if token:
            cloud.token = token
            if cloud.check_connection():
                logger.info('Cloud online.')
                print_white('Cloud service online')

                if cloud.check_token():
                    data.update_cloud_friends()
                else:
                    logger.info('Invalid token.')
                    print_white('Token invalid')

            else:
                logger.info('Cloud offline.')
                print_white('Cloud service down')
        options = {
            'type': 'list',
            'name': 'option',
            'message': 'What do you want?',
            'qmark': '@',
            'choices': [
                {
                    'name': 'Solo session               [Working]',
                    'value': 'solo'
                },
                {
                    'name': 'Whitelisted session        [Experimental]',
                    'value': 'whitelist',
                },
                {
                    'name': 'Blacklisted session        [' + ('Experimental' if len(dynamic_blacklist) > 0 else 'Not working') + ']',
                    'value': 'blacklist',
                },
                {
                    'name': 'Auto whitelisted session   [' + ('Experimental' if len(dynamic_blacklist) > 0 else 'Not working') + ']',
                    'value': 'auto_whitelist',
                },
                {
                    'name': 'Locked session             [Experimental]',
                    'value': 'lock_session',
                },
                {
                    'name': 'Diagnostics Only           [Experimental]',
                    'value': 'diagnostic',  # TODO: Actually add a diagnostic-only mode. Selecting this now would crash.
                },
                {
                    'name': 'Kick unknowns              [Unstable]',
                    'value': 'kick'
                },
                {
                    'name': 'New session                [Working]',
                    'value': 'new'
                },
                {
                    'name': 'Lists',
                    'value': 'lists'
                },
                {
                    'name': 'Kick by IP                 [Unstable]',
                    'value': 'kick_by_ip'
                },
                {
                    'name': 'Token',
                    'value': 'token'
                },
                {
                    'name': 'Support zip',
                    'value': 'support_zip'
                },
                {
                    'name': 'Quit',
                    'value': 'quit'
                }
            ]
        }
        answer = prompt(options, style=style, )
        if not answer:
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)
        os.system('cls')
        option = answer['option']

        # TODO: There's actually some fairly large optimisation available here. Concatenating strings with the '+'
        #  operator in Python is quadratic in complexity ( O(n^2) ) instead of the expected linear ( O(n) ) complexity.
        #  Appending all parts of the string as elements of a list and then using .join() is linear and i.e. faster.
        if option == 'solo':
            logger.info('Starting solo session')
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Solo session' +
                        Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')

            packet_filter = Whitelist(ips=[])
            try:
                packet_filter.start()
                while True:
                    time.sleep(10)  # this is still very terrible
            except KeyboardInterrupt:
                packet_filter.stop()
                logger.info('Stopped solo session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Solo session' +
                            Fore.LIGHTWHITE_EX + '"')
                continue

        elif option == 'whitelist':
            local_ip = get_private_ip()
            ip_set = {local_ip}
            ip_tags = [sessioninfo.IPTag(local_ip, "LOCAL IP")]
            public_ip = get_public_ip()
            if public_ip:
                ip_set.add(public_ip)
                ip_tags.append(sessioninfo.IPTag(public_ip, "PUBLIC IP"))
            else:
                print_white('Failed to get Public IP. Running without.')

            for ip, friend in custom_ips:
                if friend.get('enabled'):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        ip_set.add(ip_calc)
                        ip_tags.append(sessioninfo.IPTag(ip_calc, friend.get('name') + " [WHITELIST]"))
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue

            for ip, friend in friends:
                if friend.get('enabled'):
                    ip_set.add(ip)
                    ip_tags.append(sessioninfo.IPTag(ip, friend.get('name') + " [CLOUD]"))

            logger.info('Starting whitelisted session with {} IPs'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')

            # Exposes session information, diagnostics and behaviour.
            manager = Manager()
            connection_stats = manager.list()
            session_info = sessioninfo.SessionInfo(manager.dict(), connection_stats, manager.Queue(), ip_tags)

            logger.info("ip_tags: " + str(ip_tags))
            #logger.info("session_info: " + str(session_info))

            """ Set up packet_filter outside the try-catch so it can be safely referenced inside KeyboardInterrupt."""
            packet_filter = Whitelist(ips=ip_set, session_info=session_info)

            print("Experimental support for Online 1.54+ developed by Speyedr.\n")
                  #"Not working? Found a bug?", "https://gitlab.com/Speyedr/guardian-fastload-fix/-/issues",
                  #"(Pressing ENTER will open the link in your web browser.)", sep="\n")

            try:
                #session_info.start()
                packet_filter.start()
                while True:
                    """
                    Here is *probably* where the PacketLogger and SessionInfo classes should be managed.
                    Every [x] milliseconds the SessionInfo class will .update() with packet info (and a new print),
                    and the PacketLogger instance will be passed down to Whitelist() when initialized so the filter
                    loop can add packets to the capture. Once the session has stopped, the PacketLogger will add all
                    packets in its' memory queue to disk (or perhaps it should be sequentially writing to a file) and
                    save that file for investigation later.
                    """
                    time.sleep(10)  # this is still very terrible but might be good enough for now?
                    #input()
                    # if we reach here then the user pressed ENTER
                    #webbrowser.open("https://gitlab.com/Speyedr/guardian-fastload-fix/-/issues")
                    #time.sleep(1)      # prevents the user from opening the page a ludicrous amount of times?

                    #time.sleep(0.01)
                    #print(session_info)  # display session diagnostics
                    print(sessioninfo.generate_stats(connection_stats))
                    session_info.process_item()
                    #os.system('cls')  # refresh console
            except KeyboardInterrupt:
                packet_filter.stop()
                #session_info.stop()
                logger.info('Stopped whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'blacklist':
            local_ip = get_private_ip()
            allowed_ips = {local_ip}
            public_ip = get_public_ip()
            if public_ip:
                allowed_ips.add(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')
                
            for ip, friend in custom_ips:
                if friend.get('enabled'):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        allowed_ips.add(ip_calc)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue

            for ip, friend in friends:
                if friend.get('enabled'):
                    allowed_ips.add(ip)

            ip_set = set()
            for ip, item in blacklist:
                if item.get('enabled'):
                    try:
                        ip = IPValidator.validate_get(ip)
                        ip_set.add(ip)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue
            logger.info('Starting blacklisted session with {} IPs'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTBLACK_EX + 'Blacklist' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTBLACK_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')

            packet_filter = Blacklist(ips=ip_set, blocks=dynamic_blacklist, known_allowed=allowed_ips)
            try:
                packet_filter.start()
                while True:
                    time.sleep(10)  # this is still very terrible
            except KeyboardInterrupt:
                packet_filter.stop()
                logger.info('Stopped blacklisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTBLACK_EX + 'Blacklist' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'auto_whitelist':
            logger.info('Starting auto whitelisted session')
            collector = IPCollector(packet_count_min_threshold=15)
            logger.info('Starting to collect IPs')
            collector.start()
            for _ in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(0.5)
            collector.stop()
            ip_set = set(collector.ips)
            logger.info('Collected {} IPs'.format(len(ip_set)))
            #print("IPs: " + str(ip_set))
            print("Checking for potential tunnels in collected IPs...\n")
            potential_tunnels = set()
            for ip in ip_set:
                if util.DynamicBlacklist.ip_in_cidr_block_set(ip, dynamic_blacklist, min_cidr_suffix=0):
                    if ip not in custom_ips:    # Ignore if user has this IP in custom whitelist.
                        potential_tunnels.add(ip)
            #print("potential tunnels: ", potential_tunnels)
            if len(potential_tunnels) > 0:
                c = [{
                    'name': ip,
                    'checked': False
                } for ip in potential_tunnels]
                options = {
                    'type': 'checkbox',
                    'name': 'option',
                    'qmark': '@',
                    'message': "", 'WARNING! Guardian has detected ' + str(len(potential_tunnels)) + ' IP' +
                        ("" if len(potential_tunnels) == 1 else "s") + " in your current session that may be used for " +
                        "connection tunnelling, and may break session security if added to the whitelist.\nUnless " +
                        "you know what you're doing, " +
                        "it is HIGHLY RECOMMENDED that you DO NOT allow these IPs to be added to the whitelist.\n" +
                        "Please note that excluding an IP from this list will likely result in players connected " +
                        "through that IP to be dropped from the session.\nIf this happens, then you may have to " +
                        "check both you and your friend's Windows Firewall settings to see why they can't directly " +
                        "connect to you.\nIf this is a false-positive and you are sure an IP is a direct connection, " +
                        "you can prevent this message from appearing by manually adding them to the Custom whitelist.\n\n" +
                        "Select the potentially session security breaking IPs you wish to keep whitelisted, if any.\n"
                    'choices': c
                }
                answer = prompt(options, style=style)
                print(answer)
                if answer is not None:
                    try:
                        for ip in answer['option']:
                            potential_tunnels.remove(ip)  # Anything that has been checked will not be considered a tunnel.
                    except KeyError:
                        pass    # Probably the user pressing CTRL+C to cancel the selection, meaning no 'option' key.
                #print("potential tunnels:", potential_tunnels)

                for ip in potential_tunnels:
                    ip_set.remove(ip)

                #print("ip_set:", ip_set)

            else:
                print("No tunnels found!")
            local_ip = get_private_ip()
            ip_set.add(local_ip)
            public_ip = get_public_ip()
            if public_ip:
                ip_set.add(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')

            for ip, friend in custom_ips:
                if friend.get('enabled'):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        ip_set.add(ip_calc)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue

            for ip, friend in friends:
                if friend.get('enabled'):
                    ip_set.add(ip)

            time.sleep(5)   # to see debug prints

            os.system('cls')
            logger.info('Starting whitelisted session with {} IPs'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')

            packet_filter = Whitelist(ips=ip_set)
            try:
                packet_filter.start()
                while True:
                    time.sleep(10)  # this is still very terrible
            except KeyboardInterrupt:
                packet_filter.stop()
                logger.info('Stopping whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == "lock_session":
            os.system('cls')
            logger.info('Session will now lock. All requests to join this session should fail.')
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Locked session' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to unlock session.')

            packet_filter = Locked()
            try:
                packet_filter.start()
                while True:
                    time.sleep(10)  # this is still very terrible
            except KeyboardInterrupt:
                packet_filter.stop()
                logger.info('Stopping whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Locked session' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == "lock_whitelist":
            local_ip = get_private_ip()
            ip_set = {local_ip}
            public_ip = get_public_ip()
            if public_ip:
                ip_set.add(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')

            for ip, friend in custom_ips:
                if friend.get('enabled'):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        ip_set.add(ip_calc)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue

            for ip, friend in friends:
                if friend.get('enabled'):
                    ip_set.add(ip)

            os.system('cls')
            logger.info('Starting locked session with {} IP overrides'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Locked session w/ Whitelist override' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')

            packet_filter = LockedWhitelist(ips=ip_set)
            try:
                packet_filter.start()
                while True:
                    time.sleep(10)  # this is still very terrible
            except KeyboardInterrupt:
                packet_filter.stop()
                logger.info('Stopping locked session w/ whitelist override')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Locked session w/ Whitelist override' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'lists':
            while True:
                options = {
                    'type': 'list',
                    'name': 'option',
                    'qmark': '@',
                    'message': 'What do you want?',
                    'choices': [
                        {
                            'name': 'Custom',
                            'value': 'custom'
                        },
                        {
                            'name': 'Cloud',
                            'value': 'cloud'
                        },
                        {
                            'name': 'Blacklist',
                            'value': 'blacklist'
                        },
                        {
                            'name': 'MainMenu',
                            'value': 'return'
                        }
                    ]
                }
                if not config.get('token'):
                    options['choices'][1]['disabled'] = 'No token'
                answer = prompt(options, style=style)
                if not answer or answer['option'] == 'return':
                    os.system('cls')
                    break

                elif answer['option'] == 'custom':
                    os.system('cls')
                    while True:
                        options = {
                            'type': 'list',
                            'name': 'option',
                            'qmark': '@',
                            'message': 'Custom list',
                            'choices': [
                                {
                                    'name': 'Select',
                                    'value': 'select'
                                },
                                {
                                    'name': 'Add',
                                    'value': 'add'
                                },
                                {
                                    'name': 'List',
                                    'value': 'list'
                                },
                                {
                                    'name': 'MainMenu',
                                    'value': 'return'
                                }
                            ]
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer['option'] == 'return':
                            os.system('cls')
                            break

                        elif answer['option'] == 'select':
                            os.system('cls')
                            if len(custom_ips) <= 0:
                                print_white('No friends')
                                continue
                            else:
                                c = [{
                                    'name': f.get('name'),
                                    'checked': True if f.get('enabled') else None
                                } for ip, f in custom_ips]
                                options = {
                                    'type': 'checkbox',
                                    'name': 'option',
                                    'qmark': '@',
                                    'message': 'Select who to enable',
                                    'choices': c
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system('cls')
                                    continue
                                for ip, item in custom_ips:
                                    item['enabled'] = item.get('name') in answer['option']
                                config.save()

                        # TODO: Prevent users from accidentally adding R* / T2 IPs to the whitelist.
                        #  Perhaps this could be done by updating the validator?
                        elif answer['option'] == 'add':
                            os.system('cls')
                            options = [
                                {
                                    'type': 'input',
                                    'name': 'name',
                                    'message': 'Name',
                                    'qmark': '@',
                                    'validate': NameInCustom
                                },
                                {
                                    'type': 'input',
                                    'name': 'ip',
                                    'message': 'IP/URL',
                                    'qmark': '@',
                                    'validate': IPInCustom
                                },
                            ]

                            answer = prompt(options, style=style)
                            if not answer:
                                os.system('cls')
                                continue
                            try:
                                ip = IPValidator.validate_get(answer['ip'])
                                item = {
                                    'name': answer['name'],
                                    'enabled': True
                                }
                                if ip != answer['ip']:
                                    item['value'] = answer['ip']
                                custom_ips.add(ip, item)
                                config.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer['option'] == 'list':
                            os.system('cls')
                            while True:
                                if len(custom_ips) <= 0:
                                    print_white('No friends')
                                    break
                                else:
                                    c = [{
                                        'name': f.get('name'),
                                        'checked': True if f.get('enabled') else None
                                    } for ip, f in custom_ips]
                                    options = {
                                        'type': 'list',
                                        'name': 'name',
                                        'qmark': '@',
                                        'message': 'Select who view',
                                        'choices': c
                                    }
                                    name = prompt(options, style=style)
                                    if not name:
                                        os.system('cls')
                                        break
                                    options = {
                                        'type': 'list',
                                        'name': 'option',
                                        'qmark': '@',
                                        'message': 'Select what to do',
                                        'choices': [
                                            {
                                                'name': 'Edit',
                                                'value': 'edit'
                                            },
                                            {
                                                'name': 'Delete',
                                                'value': 'delete'
                                            },
                                            {
                                                'name': 'Back',
                                                'value': 'return'
                                            }
                                        ]
                                    }
                                    name = name['name']
                                    answer = prompt(options, style=style)
                                    if not answer or answer['option'] == 'return':
                                        os.system('cls')
                                        break

                                    elif answer['option'] == 'edit':
                                        while True:
                                            print(
                                                'Notice, user deleted. Press enter to go back / Save. Quit and you lose him.')
                                            ip, item = custom_ips.find(name)
                                            entry = item.get('value', ip)
                                            custom_ips.delete(ip)
                                            config.save()
                                            options = [
                                                {
                                                    'type': 'input',
                                                    'name': 'name',
                                                    'message': 'Name',
                                                    'qmark': '@',
                                                    'validate': NameInCustom,
                                                    'default': name
                                                },
                                                {
                                                    'type': 'input',
                                                    'name': 'ip',
                                                    'message': 'IP/URL',
                                                    'qmark': '@',
                                                    'validate': IPInCustom,
                                                    'default': entry
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            try:
                                                ip = IPValidator.validate_get(answer['ip'])
                                                item['name'] = answer['name']
                                                item['enabled'] = True
                                                if ip != answer['ip']:
                                                    item['value'] = answer['ip']
                                                custom_ips.add(ip, item)
                                                config.save()
                                                os.system('cls')
                                            except ValidationError as e:
                                                custom_ips.add(ip, item)
                                                config.save()
                                                print_white('Original item was restored due to error: '+e.message)
                                            break

                                    elif answer['option'] == 'delete':
                                        ip, item = custom_ips.find(name)
                                        custom_ips.delete(ip)
                                        config.save()

                elif answer['option'] == 'blacklist':
                    os.system('cls')
                    while True:
                        options = {
                            'type': 'list',
                            'name': 'option',
                            'qmark': '@',
                            'message': 'Blacklist',
                            'choices': [
                                {
                                    'name': 'Select',
                                    'value': 'select'
                                },
                                {
                                    'name': 'Add',
                                    'value': 'add'
                                },
                                {
                                    'name': 'List',
                                    'value': 'list'
                                },
                                {
                                    'name': 'MainMenu',
                                    'value': 'return'
                                }
                            ]
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer['option'] == 'return':
                            os.system('cls')
                            break

                        elif answer['option'] == 'select':
                            os.system('cls')
                            if len(blacklist) <= 0:
                                print_white('No ips')
                                continue
                            else:
                                c = [{
                                    'name': f.get('name'),
                                    'checked': True if f.get('enabled') else None
                                } for ip, f in blacklist]
                                options = {
                                    'type': 'checkbox',
                                    'name': 'option',
                                    'qmark': '@',
                                    'message': 'Select who to enable',
                                    'choices': c
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system('cls')
                                    continue
                                for ip, item in blacklist:
                                    item['enabled'] = item.get('name') in answer['option']
                                config.save()

                        elif answer['option'] == 'add':
                            os.system('cls')
                            options = [
                                {
                                    'type': 'input',
                                    'name': 'name',
                                    'message': 'Name',
                                    'qmark': '@',
                                    'validate': NameInBlacklist
                                },
                                {
                                    'type': 'input',
                                    'name': 'ip',
                                    'message': 'IP/URL',
                                    'qmark': '@',
                                    'validate': IPInBlacklist
                                },
                            ]

                            answer = prompt(options, style=style)
                            if not answer:
                                os.system('cls')
                                continue
                            try:
                                ip = IPValidator.validate_get(answer['ip'])
                                item = {
                                    'name': answer['name'],
                                    'enabled': True
                                }
                                if ip != answer['ip']:
                                    item['value'] = answer['ip']
                                blacklist.add(ip, item)
                                config.save()
                            except ValidationError as e:
                                print_white(e.message)

                        elif answer['option'] == 'list':
                            os.system('cls')
                            while True:
                                if len(blacklist) <= 0:
                                    print_white('No friends')
                                    break
                                else:
                                    c = [{
                                        'name': f.get('name'),
                                        'checked': True if f.get('enabled') else None
                                    } for ip, f in blacklist]
                                    options = {
                                        'type': 'list',
                                        'name': 'name',
                                        'qmark': '@',
                                        'message': 'Select who view',
                                        'choices': c
                                    }
                                    name = prompt(options, style=style)
                                    if not name:
                                        os.system('cls')
                                        break
                                    options = {
                                        'type': 'list',
                                        'name': 'option',
                                        'qmark': '@',
                                        'message': 'Select what to do',
                                        'choices': [
                                            {
                                                'name': 'Edit',
                                                'value': 'edit'
                                            },
                                            {
                                                'name': 'Delete',
                                                'value': 'delete'
                                            },
                                            {
                                                'name': 'Back',
                                                'value': 'return'
                                            }
                                        ]
                                    }
                                    name = name['name']
                                    answer = prompt(options, style=style)
                                    if not answer or answer['option'] == 'return':
                                        os.system('cls')
                                        break

                                    elif answer['option'] == 'edit':
                                        while True:
                                            print(
                                                'Notice, user deleted. Press enter to go back / Save. Quit and you lose him.')
                                            ip, item = blacklist.find(name)
                                            blacklist.delete(ip)
                                            config.save()
                                            entry = item.get('value', ip)
                                            options = [
                                                {
                                                    'type': 'input',
                                                    'name': 'name',
                                                    'message': 'Name',
                                                    'qmark': '@',
                                                    'validate': NameInBlacklist,
                                                    'default': name
                                                },
                                                {
                                                    'type': 'input',
                                                    'name': 'ip',
                                                    'message': 'IP/URL',
                                                    'qmark': '@',
                                                    'validate': IPInBlacklist,
                                                    'default': entry
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            try:
                                                ip = IPValidator.validate_get(answer['ip'])
                                                item['name'] = answer['name']
                                                item['enabled'] = True
                                                if ip != answer['ip']:
                                                    item['value'] = answer['ip']
                                                blacklist.add(ip, item)
                                                config.save()
                                                os.system('cls')
                                            except ValidationError as e:
                                                blacklist.add(ip, item)
                                                config.save()
                                                print_white('Original item was restored due to error: '+e.message)
                                            break

                                    elif answer['option'] == 'delete':
                                        ip, item = blacklist.find(name)
                                        blacklist.delete(ip)
                                        config.save()

                elif answer['option'] == 'cloud':
                    os.system('cls')
                    while True:
                        options = {
                            'type': 'list',
                            'name': 'option',
                            'qmark': '@',
                            'message': 'Custom list',
                            'choices': [
                                {
                                    'name': 'Select',
                                    'value': 'select'
                                },
                                {
                                    'name': 'Permission',
                                    'value': 'permission'
                                },
                                {
                                    'name': 'Return',
                                    'value': 'return'
                                }
                            ]
                        }
                        answer = prompt(options, style=style)

                        if not answer or answer['option'] == 'return':
                            os.system('cls')
                            break

                        elif answer['option'] == 'select':
                            os.system('cls')
                            data.update_cloud_friends()
                            if len(friends) <= 0:
                                print_white('No friends')
                                break
                            else:
                                options = {
                                    'type': 'checkbox',
                                    'name': 'option',
                                    'qmark': '@',
                                    'message': 'Select who to enable',
                                    'choices': [{
                                        'name': f.get('name'),
                                        'value': f.get('name'),
                                        'checked': True if f.get('enabled') else None,
                                    } for ip, f in friends]
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system('cls')
                                    break
                                for ip, f in friends:
                                    f['enabled'] = f.get('name') in answer['option']
                                config.save()

                        elif answer['option'] == 'permission':
                            os.system('cls')
                            while True:
                                token = config.get('token')
                                cloud = networkmanager.Cloud(token)
                                if not cloud.check_connection():
                                    print_white('Cloud service down')
                                    break

                                options = {
                                    'type': 'list',
                                    'name': 'option',
                                    'qmark': '@',
                                    'message': 'Custom list',
                                    'choices': [
                                        {
                                            'name': 'Revoke permission',
                                            'value': 'revoke'
                                        },
                                        {
                                            'name': 'Request permission',
                                            'value': 'request'
                                        },
                                        {
                                            'name': 'Pending requests',
                                            'value': 'pending'
                                        },
                                        {
                                            'name': 'Return',
                                            'value': 'return'
                                        }
                                    ]
                                }
                                answer = prompt(options, style=style)
                                if not answer or answer['option'] == 'return':
                                    os.system('cls')
                                    break

                                elif answer['option'] == 'revoke':
                                    # My perms
                                    os.system('cls')
                                    while True:
                                        allowed_ips = cloud.get_allowed()
                                        if len(allowed_ips) <= 0:
                                            print_white('None')
                                            break
                                        options = {
                                            'type': 'list',
                                            'name': 'option',
                                            'qmark': '@',
                                            'message': 'Who to revoke',
                                            'choices': [f.get('name') for f in allowed_ips]
                                        }
                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system('cls')
                                            break
                                        name = answer['option']
                                        code, msg = cloud.revoke(name)
                                        if code == 200:
                                            print_white('Revoked')
                                        else:
                                            print_white('{}'.format(msg.get('error')))

                                elif answer['option'] == 'request':
                                    # My friends who I don't have perms from
                                    os.system('cls')
                                    while True:
                                        friends = cloud.get_all()
                                        if len(friends) <= 0:
                                            print_white('No friends')
                                            break
                                        options = {
                                            'type': 'list',
                                            'name': 'option',
                                            'qmark': '@',
                                            'message': 'Request from who',
                                            'choices': [f.get('name') for ip, f in friends]
                                        }
                                        answer = prompt(options, style=style)
                                        if not answer:
                                            os.system('cls')
                                            break
                                        name = answer['option']
                                        result, msg = cloud.request(name)
                                        if result:
                                            print_white('Request sent')
                                        else:
                                            print_white('{}'.format(msg))

                                elif answer['option'] == 'pending':
                                    # friends who requested permission from me
                                    os.system('cls')
                                    while True:
                                        pending = cloud.get_pending()
                                        if len(pending) <= 0:
                                            print_white('None')
                                            break
                                        options = {
                                            'type': 'list',
                                            'name': 'option',
                                            'qmark': '@',
                                            'message': 'Select user',
                                            'choices': [f.get('name') for f in pending]
                                        }
                                        answer = prompt(options, style=style)
                                        name = answer['option']
                                        if not answer:
                                            os.system('cls')
                                            break

                                        options = {
                                            'type': 'list',
                                            'name': 'option',
                                            'qmark': '@',
                                            'message': 'Option',
                                            'choices': [
                                                {
                                                    'name': 'Decline',
                                                    'value': 'decline'
                                                },
                                                {
                                                    'name': 'Accept',
                                                    'value': 'accept'
                                                },
                                                {
                                                    'name': 'Return',
                                                    'value': 'return'
                                                }
                                            ]
                                        }
                                        answer = prompt(options, style=style)

                                        if not answer or answer['option'] == 'return':
                                            os.system('cls')
                                            break
                                        elif answer['option'] == 'accept':
                                            result, msg = cloud.accept(name)
                                            if result:
                                                print_white('Accepted')
                                            else:
                                                print_white('{}'.format(msg))

                                        elif answer['option'] == 'decline':
                                            result, msg = cloud.revoke(name)
                                            if result:
                                                print_white('Request declined')
                                            else:
                                                print_white('{}'.format(msg))

        elif option == 'kick_by_ip':
            collector = IPCollector()
            collector.start()
            for _ in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(1)
            collector.stop()
            ip_set = set(collector.ips)
            os.system('cls')
            if len(ip_set) <= 0:
                print_white('None')
                break
            options = {
                'type': 'checkbox',
                'name': 'option',
                'qmark': '@',
                'message': 'Select IP\'s to kick',
                'choices': [ip for ip in ip_set]
            }
            answer = prompt(options, style=style)
            if not answer:
                os.system('cls')
                break

            ips = answer['option']
            print_white('Running: "' +
                        Fore.LIGHTBLACK_EX + 'Blacklist' +
                        Fore.LIGHTWHITE_EX + '"')
            packet_filter = Blacklist(ips=ips)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()

        elif option == 'kick':
            local_ip = get_private_ip()
            ip_set = {local_ip}
            public_ip = get_public_ip()
            if public_ip:
                ip_set.add(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')
            for ip, friend in custom_ips:
                if friend.get('enabled'):
                    try:
                        ip_calc = IPValidator.validate_get(ip)
                        ip_set.add(ip_calc)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(ip))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(ip) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue

            for ip, friend in friends:
                if friend.get('enabled'):
                    ip_set.add(ip)
            print_white('Kicking unknowns')
            time.sleep(2)
            packet_filter = Whitelist(ips=ip_set)
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == 'new':
            print_white('Creating new session')
            time.sleep(2)
            packet_filter = Whitelist(ips=[])
            packet_filter.start()
            time.sleep(10)
            packet_filter.stop()
            continue

        elif option == 'token':
            token = config.get('token')
            options = {
                'type': 'input',
                'name': 'token',
                'qmark': '@',
                'message': 'Paste your token:',
                'validate': ValidateToken
            }
            if token:
                options['default'] = token
            answer = prompt(options, style=style)
            if not answer:
                os.system('cls')
                continue
            config.set('token', answer['token'])
            config.save()
            os.system('cls')
            print_white('New token: "' +
                        Fore.LIGHTCYAN_EX + answer['token'] +
                        Fore.LIGHTWHITE_EX + '"')

        elif option == 'support_zip':
            os.system('cls')
            print_white('NOTICE: This program will now log all udp traffic on port 6672 for 1 minute. '
                        'Only run this if you are okay with that.')
            options = {
                'type': 'confirm',
                'name': 'agree',
                'qmark': '@',
                'message': 'Agree?'
            }
            answer = prompt(options, style=style)
            if not answer:
                os.system('cls')
                continue
            if answer.get('agree'):
                local_list = config.get('custom_ips')
                cloud_list = config.get('friends')
                ip_set = []
                for friend in local_list:
                    if friend.get('enabled'):
                        try:
                            ip = IPValidator.validate_get(friend.get('ip'))
                            ip_set.append(ip)
                        except ValidationError:
                            continue
                for friend in cloud_list:
                    if friend.get('enabled'):
                        ip_set.append(friend.get('ip'))
                debugger = Debugger(ip_set)
                debugger.start()
                for _ in tqdm(range(60), ascii=True, desc='Collecting Requests'):
                    time.sleep(1)
                debugger.stop()
                time.sleep(1)
                print_white('Collecting data')
                token = config.get('token')
                print_white('Checking connections')
                runner = networkmanager.Cloud()
                if runner.check_connection():
                    da_status = 'Online'
                else:
                    da_status = 'Offline'
                if da_status and token:
                    runner = networkmanager.Cloud(token)
                    if da_status == 'Online':
                        if runner.check_token():
                            has_token = 'Has a valid token'
                        else:
                            has_token = 'Has a invalid token'
                    else:
                        has_token = 'Has token but could not check it'
                else:
                    has_token = 'Does not have a token'

                datas = {
                    'token': has_token,
                    'da_status': da_status,
                    'customlist': custom_ips,
                    'cloud': friends
                }

                print_white('Writing data')
                with open("datacheck.json", "w+") as datafile:
                    json.dump(datas, datafile, indent=2)
                print_white('Packing debug request')
                compressed = zipfile.ZipFile('debugger-{}.zip'.format(time.strftime("%Y%m%d-%H%M%S")), "w",
                                             zipfile.ZIP_DEFLATED)
                compressed.write('datacheck.json')
                try:
                    compressed.write('debugger.log')
                except FileNotFoundError:
                    pass
                os.remove('datacheck.json')
                try:
                    os.remove('debugger.log')
                except FileNotFoundError:
                    pass
                print_white('Finished')
                compressed.close()
                continue
            else:
                print_white('Declined')
                continue

        elif option == 'quit':
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)


if __name__ == '__main__':
    freeze_support()

    success = False
    while not success:
        try:
            config = data.ConfigData(data.file_name)
            success = True  # if we reach here then config was parsed successfully
        except Exception as e:
            # config file could not be loaded. either file creation failed or data.json is corrupt.
            if not os.path.isfile(data.file_name):
                # could not create config. fatal error. MB_OK is 0x0, MB_ICON_ERROR is 0x10
                ctypes.windll.user32.MessageBoxW(None, f"FATAL: Guardian could not create the config file {data.file_name}.\n\n"
                                                       f"Press 'Ok' to close the program.",
                                                 f"Fatal Error", 0x0 | 0x10)
                raise e     # could call sys.exit instead but I think raising again is more sensible
            else:
                # MB_ABORTRETRYIGNORE is 0x2, MB_ICON_ERROR is 0x10
                choice = ctypes.windll.user32.MessageBoxW(None, f"Guardian could not load the config file {data.file_name}.\n\n"
                                                   f"The most common reason for this error is that the file is corrupt.\n\n"
                                                   f"Press 'Abort' to close Guardian, press 'Retry' to load the config again, "
                                                   f"or press 'Ignore' to \"Refresh\" Guardian by renaming the corrupt "
                                                   f"config file and creating a new one.",
                                                          f"Error", 0x2 | 0x10)
                # ID_ABORT = 0x3, ID_RETRY = 0x4, ID_IGNORE = 0x5
                if choice == 0x3:
                    sys.exit(-2)
                elif choice == 0x4:
                    pass  # we'll hit the bottom of the loop and try again
                else:
                    char_set = string.ascii_lowercase + string.digits
                    random_string = "".join(random.choice(char_set) for _ in range(8)) # generate 8 random chars
                    separator = data.file_name.rindex('.')
                    new_name = data.file_name[:separator] + '_' + random_string + data.file_name[separator:]
                    os.rename(data.file_name, new_name)
                    # file has been renamed, try again

    # at this point the file has been parsed and is valid--any additional exceptions are explicit or programmer error
    try:
        blacklist = data.CustomList('blacklist')
        custom_ips = data.CustomList('custom_ips')
        friends = data.CustomList('friends')
    except data.MigrationRequired:
        data.migrate_to_dict()
        time.sleep(5)
        sys.exit()

    os.system('cls')
    logger.info('Init')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print_white('Please start as administrator')
        logger.info('Started without admin')
        input('Press enter to exit.')
        sys.exit()
    logger.info('Booting up')
    print_white('Booting up...')
    if not pydivert.WinDivert.is_registered():
        pydivert.WinDivert.register()
    ctypes.windll.kernel32.SetConsoleTitleW('Guardian {}'.format(version))
    cloud = networkmanager.Cloud()
    ipsyncer = IPSyncer(None)
    print_white('Building dynamic blacklist...')
    dynamic_blacklist = set()
    try:
        #  TODO: Guardian does not correctly locally save files when run from command prompt outside of Guardian folder.
        dynamic_blacklist = util.DynamicBlacklist.get_dynamic_blacklist("db.json")
    except (util.DynamicBlacklist.ScrapeError, RequestException, json.decoder.JSONDecodeError, IndexError, ValueError, TypeError, KeyError, FileNotFoundError) as e:
        print_white('ERROR: Could not construct dynamic blacklist: ' + str(e) +
                    '\nAuto-Whitelist and Blacklist will not work correctly.')
        time.sleep(3)
    print_white('Checking connections.')
    if cloud.check_connection():
        version = cloud.version()
        version = version.get('version', None) if version else None
        if version:
            if StrictVersion(version) > StrictVersion(version):
                os.system('cls')
                print_white('An update was found.')
                options = {
                    'type': 'confirm',
                    'message': 'Open browser?',
                    'name': 'option',
                    'qmark': '@',
                    'default': True
                }
                answer = prompt(options, style=style)
                if answer['option']:
                    webbrowser.open('https://www.thedigitalarc.com/software/Guardian')
        token = config.get('token')
        if token:
            cloud.token = token
            if cloud.check_token():
                ipsyncer.token = token
                ipsyncer.start()
                print_white('Starting IP syncer.')
    while True:
        try:
            main()
        except KeyboardInterrupt:
            continue
        finally:
            ipsyncer.stop()
