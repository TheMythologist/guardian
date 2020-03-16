from __future__ import print_function, unicode_literals
from questionary import Validator, ValidationError, prompt
from prompt_toolkit.styles import Style
import os
import ctypes
import data
from colorama import Fore
from network.blocker import *
import pydivert
import sys
from multiprocessing import freeze_support
import ipaddress
from operator import itemgetter
from network import networkmanager
from distutils.version import StrictVersion
import webbrowser
import socket
from tqdm import tqdm
import zipfile
import json
import requests
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
    try:
        public_ip = networkmanager.Cloud().get_ip()
        logger.info('Got a public IP')
        return public_ip
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        logger.warning('Failed to get public IP')
        return False


class NameInCustom(Validator):
    def validate(self, document):
        config = data.read_file()
        if any(x['name'] == document.text for x in config['custom_ips']):
            raise ValidationError(
                message='Name already in list',
                cursor_position=len(document.text))  # Move cursor to end


class NameInBlacklist(Validator):
    def validate(self, document):
        config = data.read_file()
        if any(x['name'] == document.text for x in config['blacklist']):
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
            else:
                ip = socket.gethostbyname(document.text)
                ipaddress.IPv4Address(ip)
            return ip
        except ipaddress.AddressValueError:
            raise error


class IPInCustom(IPValidator):
    def validate(self, document):
        super().validate(document)
        config = data.read_file()
        if any(x['ip'] == document.text for x in config['custom_ips']):
            raise ValidationError(
                message='IP already in list',
                cursor_position=len(document.text))  # Move cursor to end


class IPInBlacklist(Validator):
    def validate(self, document):
        super().validate(document)
        config = data.read_file()
        if any(x['ip'] == document.text for x in config['blacklist']):
            raise ValidationError(
                message='IP already in list',
                cursor_position=len(document.text))  # Move cursor to end


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
    while True:
        token = data.read_file().get('token')
        if token:
            conn = networkmanager.Cloud(token)
            if conn.check_connection():
                logger.info('Cloud online.')
                print_white('Cloud service online')

                if conn.check_token():
                    data.cloud_friends()
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
                    whitelist = Whitelist(ips=[])
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopped solo session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Solo session' +
                            Fore.LIGHTWHITE_EX + '"')
                continue

        elif option == 'whitelist':
            config = data.read_file()
            local_list = config.get('custom_ips')
            cloud_list = config.get('friends')
            soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            soc.connect(("8.8.8.8", 80))
            local_ip = soc.getsockname()[0]
            soc.close()
            mylist = [local_ip]
            public_ip = get_public_ip()
            if public_ip:
                mylist.append(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')

            for x in local_list:
                if x.get('enabled'):
                    try:
                        ip = IPValidator().validate({'text': x.get('ip')})
                        mylist.append(ip)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(x.get('ip')))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(x.get('ip')) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            logger.info('Starting whitelisted session with {} IPs'.format(len(mylist)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    whitelist = Whitelist(ips=mylist)
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                logger.info('Stopped whitelisted session')
                print_white('Stopped: "' +
                            Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                            Fore.LIGHTWHITE_EX + '"')

        elif option == 'blacklist':
            config = data.read_file()
            blacklist = config.get('blacklist')
            mylist = []
            for x in blacklist:
                if x.get('enabled'):
                    try:
                        ip = IPValidator().validate({'text': x.get('ip')})
                        mylist.append(ip)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(x.get('ip')))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(x.get('ip')) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue
            logger.info('Starting blacklisted session with {} IPs'.format(len(mylist)))
            print_white('Running: "' +
                        Fore.LIGHTBLACK_EX + 'Blacklist' +
                        Fore.LIGHTWHITE_EX + '" Press "' +
                        Fore.LIGHTBLACK_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    blacklist = Blacklist(ips=mylist)
                    blacklist.start()
                    time.sleep(10)
                    blacklist.stop()
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
            for i in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(1)
            collector.stop()
            mylist = list(set(collector.ips))
            logger.info('Collected {} IPs'.format(len(mylist)))
            soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            soc.connect(("8.8.8.8", 80))
            local_ip = soc.getsockname()[0]
            soc.close()
            public_ip = get_public_ip()
            if public_ip:
                mylist.append(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')
            mylist.append(local_ip)
            config = data.read_file()
            local_list = config.get('custom_ips')
            cloud_list = config.get('friends')
            for x in local_list:
                if x.get('enabled'):
                    try:
                        ip = IPValidator().validate({'text': x.get('ip')})
                        mylist.append(ip)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(x.get('ip')))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(x.get('ip')) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            mylist = list(set(mylist))
            os.system('cls')
            logger.info('Starting whitelisted session with {} IPs'.format(len(mylist)))
            print_white('Running: "' +
                        Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                        Fore.LIGHTCYAN_EX + 'CTRL + C' +
                        Fore.LIGHTWHITE_EX + '" to stop.')
            try:
                while True:
                    whitelist = Whitelist(ips=mylist)
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
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
                config = data.read_file()
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
                            config = data.read_file()
                            c = []
                            if len(config['custom_ips']) <= 0:
                                print_white('No friends')
                                continue
                            else:
                                for v in config['custom_ips']:
                                    c.append({
                                        'name': v.get('name'),
                                        'checked': True if v.get('enabled') else None,
                                    })
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
                                for v in config['custom_ips']:
                                    if v['name'] in answer['option']:
                                        v['enabled'] = True
                                    else:
                                        v['enabled'] = False
                                data.save_file(config)

                        elif answer['option'] == 'add':
                            os.system('cls')
                            config = data.read_file()
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
                            config['custom_ips'].append({
                                'name': answer['name'],
                                'ip': answer['ip'],
                                'enabled': True
                            })
                            config['custom_ips'][:] = sorted(config['custom_ips'], key=itemgetter('name'))
                            data.save_file(config)

                        elif answer['option'] == 'list':
                            os.system('cls')
                            while True:
                                config = data.read_file()
                                c = []
                                if len(config['custom_ips']) <= 0:
                                    print_white('No friends')
                                    break
                                else:
                                    for v in config['custom_ips']:
                                        c.append({
                                            'name': v.get('name'),
                                            'checked': True if v.get('enabled') else None,
                                        })
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
                                            config = data.read_file()
                                            ip = [d for d in config['custom_ips'] if d.get('name') == name][0].get('ip')
                                            config['custom_ips'][:] = [d for d in config['custom_ips'] if
                                                                       d.get('name') != name]
                                            data.save_file(config)
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
                                                    'default': ip
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            config['custom_ips'].append({
                                                'name': answer['name'],
                                                'ip': answer['ip'],
                                                'enabled': False
                                            })
                                            config['custom_ips'][:] = sorted(config['custom_ips'],
                                                                             key=itemgetter('name'))
                                            data.save_file(config)
                                            os.system('cls')
                                            break

                                    elif answer['option'] == 'delete':
                                        config = data.read_file()
                                        config['custom_ips'][:] = [d for d in config['custom_ips'] if
                                                                   d.get('name') != name]
                                        data.save_file(config)

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
                            config = data.read_file()
                            c = []
                            if len(config['blacklist']) <= 0:
                                print_white('No ips')
                                continue
                            else:
                                for v in config['blacklist']:
                                    c.append({
                                        'name': v.get('name'),
                                        'checked': True if v.get('enabled') else None,
                                    })
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
                                for v in config['blacklist']:
                                    if v['name'] in answer['option']:
                                        v['enabled'] = True
                                    else:
                                        v['enabled'] = False
                                data.save_file(config)

                        elif answer['option'] == 'add':
                            os.system('cls')
                            config = data.read_file()
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
                            config['blacklist'].append({
                                'name': answer['name'],
                                'ip': answer['ip'],
                                'enabled': True
                            })
                            config['blacklist'][:] = sorted(config['blacklist'], key=itemgetter('name'))
                            data.save_file(config)

                        elif answer['option'] == 'list':
                            os.system('cls')
                            while True:
                                config = data.read_file()
                                c = []
                                if len(config['blacklist']) <= 0:
                                    print_white('No friends')
                                    break
                                else:
                                    for v in config['blacklist']:
                                        c.append({
                                            'name': v.get('name'),
                                            'checked': True if v.get('enabled') else None,
                                        })
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
                                            config = data.read_file()
                                            ip = [d for d in config['blacklist'] if d.get('name') == name][0].get('ip')
                                            config['blacklist'][:] = [d for d in config['blacklist'] if
                                                                      d.get('name') != name]
                                            data.save_file(config)
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
                                                    'default': ip
                                                },
                                            ]

                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            config['blacklist'].append({
                                                'name': answer['name'],
                                                'ip': answer['ip'],
                                                'enabled': False
                                            })
                                            config['blacklist'][:] = sorted(config['blacklist'],
                                                                            key=itemgetter('name'))
                                            data.save_file(config)
                                            os.system('cls')
                                            break

                                    elif answer['option'] == 'delete':
                                        config = data.read_file()
                                        config['blacklist'][:] = [d for d in config['blacklist'] if
                                                                  d.get('name') != name]
                                        data.save_file(config)

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
                            data.cloud_friends()
                            config = data.read_file()
                            friends = config['friends']
                            d = []
                            if len(friends) <= 0:
                                print_white('No friends')
                                break
                            else:
                                for v in friends:
                                    d.append({
                                        'name': v.get('name'),
                                        'value': v.get('name'),
                                        'checked': True if v.get('enabled') else None,
                                    })
                                options = {
                                    'type': 'checkbox',
                                    'name': 'option',
                                    'qmark': '@',
                                    'message': 'Select who to enable',
                                    'choices': d
                                }
                                answer = prompt(options, style=style)
                                if not answer:
                                    os.system('cls')
                                    break
                                for v in friends:
                                    if v['name'] in answer['option']:
                                        v['enabled'] = True
                                    else:
                                        v['enabled'] = False
                                data.save_file(config)

                        elif answer['option'] == 'permission':
                            os.system('cls')
                            while True:
                                config = data.read_file()
                                token = config.get('token')
                                conn = networkmanager.Cloud(token)
                                if not conn.check_connection():
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
                                        code, friends = conn.get_friends()
                                        d = []
                                        if len(friends.get('givenperm')) <= 0:
                                            print_white('None')
                                            break
                                        else:
                                            for x in friends.get('givenperm'):
                                                d.append({'name': x.get('name')})
                                            options = {
                                                'type': 'list',
                                                'name': 'option',
                                                'qmark': '@',
                                                'message': 'Who to revoke',
                                                'choices': d
                                            }
                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            name = answer['option']
                                            code, msg = conn.revoke(name)
                                            if code == 200:
                                                print_white('Revoked')
                                            else:
                                                print_white('{}'.format(msg.get('error')))

                                elif answer['option'] == 'request':
                                    # My friends who I don't have perms from
                                    os.system('cls')
                                    while True:
                                        code, friends = conn.get_all()
                                        d = []
                                        if len(friends.get('friends')) <= 0:
                                            print_white('No friends')
                                            break
                                        else:
                                            for x in friends.get('friends'):
                                                d.append({'name': x.get('name')})
                                            options = {
                                                'type': 'list',
                                                'name': 'option',
                                                'qmark': '@',
                                                'message': 'Request from who',
                                                'choices': d
                                            }
                                            answer = prompt(options, style=style)
                                            if not answer:
                                                os.system('cls')
                                                break
                                            name = answer['option']
                                            code, msg = conn.request(name)
                                            if code == 200:
                                                print_white('Request sent')
                                            else:
                                                print_white('{}'.format(msg.get('error')))

                                elif answer['option'] == 'pending':
                                    # friends who requested permission from me
                                    os.system('cls')
                                    while True:
                                        code, friends = conn.get_pending()
                                        d = []
                                        if len(friends.get('pending')) <= 0:
                                            print_white('None')
                                            break
                                        else:
                                            for x in friends.get('pending'):
                                                d.append({'name': x.get('name')})
                                            options = {
                                                'type': 'list',
                                                'name': 'option',
                                                'qmark': '@',
                                                'message': 'Select user',
                                                'choices': d
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
                                            code, msg = conn.accept(name)
                                            if code == 200:
                                                print_white('Accepted')
                                            else:
                                                print_white('{}'.format(msg.get('error')))

                                        elif answer['option'] == 'decline':
                                            code, msg = conn.revoke(name)
                                            if code == 200:
                                                print_white('Request declined')
                                            else:
                                                print_white('{}'.format(msg.get('error')))

        elif option == 'kick_by_ip':
            collector = IPCollector()
            collector.start()
            for i in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(1)
            collector.stop()
            mylist = collector.ips
            mylist = list(set(mylist))
            os.system('cls')
            d = []
            if len(mylist) <= 0:
                print_white('None')
                break
            else:
                for x in mylist:
                    d.append({'name': x})
                options = {
                    'type': 'checkbox',
                    'name': 'option',
                    'qmark': '@',
                    'message': 'Select IP\'s to kick',
                    'choices': d
                }
                answer = prompt(options, style=style)
                if not answer:
                    os.system('cls')
                    break
            ips = answer['option']
            print_white('Running: "' +
                        Fore.LIGHTBLACK_EX + 'Blacklist' +
                        Fore.LIGHTWHITE_EX + '"')
            blacklist = Blacklist(ips=ips)
            blacklist.start()
            time.sleep(10)
            blacklist.stop()

        elif option == 'kick':
            config = data.read_file()
            local_list = config.get('custom_ips')
            cloud_list = config.get('friends')
            soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            soc.connect(("8.8.8.8", 80))
            local_ip = soc.getsockname()[0]
            soc.close()
            mylist = [local_ip]
            public_ip = get_public_ip()
            if public_ip:
                mylist.append(public_ip)
            else:
                print_white('Failed to get Public IP. Running without.')
            for x in local_list:
                if x.get('enabled'):
                    try:
                        ip = IPValidator().validate({'text': x.get('ip')})
                        mylist.append(ip)
                    except ValidationError:
                        logger.warning('Not valid IP or URL: {}'.format(x.get('ip')))
                        print_white('Not valid IP or URL: "' +
                                    Fore.LIGHTCYAN_EX + '{}'.format(x.get('ip')) +
                                    Fore.LIGHTWHITE_EX + '"')
                        continue
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            print_white('Kicking unknowns')
            time.sleep(2)
            whitelist = Whitelist(ips=mylist)
            whitelist.start()
            time.sleep(10)
            whitelist.stop()
            continue

        elif option == 'new':
            print_white('Creating new session')
            time.sleep(2)
            whitelist = Whitelist(ips=[])
            whitelist.start()
            time.sleep(10)
            whitelist.stop()
            continue

        elif option == 'token':
            config = data.read_file()
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
            config['token'] = answer['token']
            data.save_file(config)
            os.system('cls')
            print_white('New token: "' +
                        Fore.LIGHTCYAN_EX + answer['token'] +
                        Fore.LIGHTWHITE_EX + '"')

        elif option == 'support_zip':
            os.system('cls')
            config = data.read_file()
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
                mylist = []
                for x in local_list:
                    if x.get('enabled'):
                        try:
                            ip = IPValidator().validate({'text': x.get('ip')})
                            mylist.append(ip)
                        except ValidationError:
                            continue
                for x in cloud_list:
                    if x.get('enabled'):
                        mylist.append(x.get('ip'))
                debugger = Debugger(mylist)
                debugger.start()
                for _ in tqdm(range(60), ascii=True, desc='Collecting Requests'):
                    time.sleep(1)
                debugger.stop()
                time.sleep(1)
                print_white('Collecting data')
                customlist = config.get('custom_ips')
                cloudlist = config.get('friends')
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
                    'customlist': customlist,
                    'cloud': cloudlist
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
    conn = networkmanager.Cloud('')
    print_white('Checking connections.')
    if conn.check_connection():
        code, cversion = conn.version()
        if code == 200:
            if cversion.get('version'):
                if StrictVersion(cversion.get('version')) > StrictVersion(version):
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
        config = data.read_file()
        token = config.get('token')
        if token:
            conn = networkmanager.Cloud(token)
            if conn.check_token():
                ipsyncer = IPSyncer(token)
                ipsyncer.start()
                print_white('Starting IP syncer.')
    while True:
        try:
            main()
        except KeyboardInterrupt:
            continue
