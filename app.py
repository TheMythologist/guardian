from __future__ import print_function, unicode_literals
from questionary import Validator, ValidationError, prompt
from prompt_toolkit.styles import Style
import os
import ctypes
from colorama import Fore
from network.blocker import *
import pydivert
import sys
from multiprocessing import freeze_support
import ipaddress
from network import networkmanager
from distutils.version import StrictVersion
import webbrowser
import socket
from tqdm import tqdm
import zipfile
import json
import time
import logging

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

version = '3.0.2'

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
    global cloud, config, custom_ips, blacklist, friends
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
                    'name': 'Solo session',
                    'value': 'solo'
                },
                {
                    'name': 'Whitelisted session',
                    'value': 'whitelist',
                },
                {
                    'name': 'Blacklisted session',
                    'value': 'blacklist',
                },
                {
                    'name': 'Auto whitelisted session',
                    'value': 'auto_whitelist',
                },
                {
                    'name': 'Kick unknowns',
                    'value': 'kick'
                },
                {
                    'name': 'New session',
                    'value': 'new'
                },
                {
                    'name': 'Lists',
                    'value': 'lists'
                },
                {
                    'name': 'Kick by IP',
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
        answer = prompt(options, style=style)
        if not answer:
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)
        os.system('cls')
        option = answer['option']

        if option == 'solo':
            logger.info('Starting solo session')
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Solo session' +
                        Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    packet_filter = Whitelist(ips=[])
                    packet_filter.start()
                    time.sleep(10)
                    packet_filter.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopped solo session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Solo session' +
                            Fore.LIGHTWHITE_EX + '"')
                continue

        elif option == 'whitelist':
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

            logger.info('Starting whitelisted session with {} IPs'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    packet_filter = Whitelist(ips=ip_set)
                    packet_filter.start()
                    time.sleep(10)
                    packet_filter.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopped whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'blacklist':
            ip_set = set()
            for ip, item in blacklist:
                if item.get('enabled'):
                    try:
                        ip = IPValidator.validate_get(item.get('ip'))
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
            try:
                while True:
                    packet_filter = Blacklist(ips=ip_set)
                    packet_filter.start()
                    time.sleep(10)
                    packet_filter.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopped blacklisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTBLACK_EX + 'Blacklist' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'auto_whitelist':
            logger.info('Starting auto whitelisted session')
            collector = IPCollector()
            logger.info('Starting to collect IPs')
            collector.start()
            for _ in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(1)
            collector.stop()
            ip_set = set(collector.ips)
            logger.info('Collected {} IPs'.format(len(ip_set)))
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

            os.system('cls')
            logger.info('Starting whitelisted session with {} IPs'.format(len(ip_set)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    packet_filter = Whitelist(ips=ip_set)
                    packet_filter.start()
                    time.sleep(10)
                    packet_filter.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopping whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Whitelisted session' +
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
                                        allowed = cloud.get_allowed()
                                        if len(allowed) <= 0:
                                            print_white('None')
                                            break
                                        options = {
                                            'type': 'list',
                                            'name': 'option',
                                            'qmark': '@',
                                            'message': 'Who to revoke',
                                            'choices': [f.get('name') for f in allowed]
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
    config = data.ConfigData(data.file_name)
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
