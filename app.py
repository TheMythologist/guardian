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

LF_FACESIZE = 32
STD_OUTPUT_HANDLE = -11

version = '3.0.2'

style = Style([
    ('qmark', 'fg:#00FFFF bold'),     # token in front of the question
    ('question', 'bold'),             # question text
    ('answer', 'fg:#00FFFF bold'),    # submitted answer text behind the question
    ('pointer', 'fg:#00FFFF bold'),   # pointer used in select and checkbox prompts
    ('selected', 'fg:#FFFFFF bold'),       # style for a selected item of a checkbox
    ('separator', 'fg:#00FFFF'),      # separator in lists
    ('instruction', '')               # user instructions for select, rawselect, checkbox
])


def get_public_ip():
    try:
        public_ip = networkmanager.Cloud().get_ip()
        Logger().info('Got a public IP')
        return public_ip
    except requests.exceptions.SSLError:
        Logger().warning('Failed to get public IP')
        return False


class Logger:

    def writer(self, type, text):
        with open('history.log', 'a+') as file:
            file.write('[{}][{}] '.format(time.strftime("%Y-%m-%d %H:%M:%S"), type) + text + '\n')

    def info(self, text):
        self.writer(type='INFO', text=text)

    def error(self, text):
        self.writer(type='ERROR', text=text)

    def warning(self, text):
        self.writer(type='WARNING', text=text)


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


class IPInCustom(Validator):
    def validate(self, document):
        config = data.read_file()
        try:
            ipaddress.IPv4Address(document.text)
        except ipaddress.AddressValueError:
            m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$', document.text)
            if m:
                pass
            else:
                raise ValidationError(
                    message='Not a valid IP or URL',
                    cursor_position=len(document.text))  # Move cursor to end
        if any(x['ip'] == document.text for x in config['custom_ips']):
            raise ValidationError(
                message='IP already in list',
                cursor_position=len(document.text))  # Move cursor to end


class IPInBlacklist(Validator):
    def validate(self, document):
        config = data.read_file()
        try:
            ipaddress.IPv4Address(document.text)
        except ipaddress.AddressValueError:
            m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$', document.text)
            if m:
                pass
            else:
                raise ValidationError(
                    message='Not a valid IP or URL',
                    cursor_position=len(document.text))  # Move cursor to end
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
                Logger().info('Cloud online.')
                print(Fore.LIGHTWHITE_EX + 'Cloud service online' + Fore.RESET)

                if conn.check_token():
                    data.cloud_friends()
                else:
                    Logger().info('Invalid token.')
                    print(Fore.LIGHTWHITE_EX + 'Token invalid' + Fore.RESET)

            else:
                Logger().info('Cloud offline.')
                print(Fore.LIGHTWHITE_EX + 'Cloud service down' + Fore.RESET)

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
            Logger().info('Starting solo session')
            print(Fore.LIGHTWHITE_EX + 'Running: "' + Fore.LIGHTCYAN_EX + 'Solo session' +
                  Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTCYAN_EX + 'CTRL + C' + Fore.LIGHTWHITE_EX +
                  '" to stop.' + Fore.RESET)
            try:
                while True:
                    whitelist = Whitelist(ips=[])
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                Logger().info('Stopped solo session')
                print(
                    Fore.LIGHTWHITE_EX + 'Stopped: "' + Fore.LIGHTCYAN_EX + 'Solo session' +
                    Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
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
                print(
                    Fore.LIGHTWHITE_EX + 'Failed to get Public IP. Running without.' + Fore.RESET)

            for x in local_list:
                if x.get('enabled'):
                    try:
                        ipaddress.IPv4Address(x.get('ip'))
                        mylist.append(x.get('ip'))
                    except ipaddress.AddressValueError:
                        m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$',
                                      x.get('ip'))
                        if m:
                            try:
                                ip = socket.gethostbyname(x.get('ip'))
                                try:
                                    ipaddress.IPv4Address(ip)
                                    mylist.append(ip)
                                except ipaddress.AddressValueError:
                                    Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                                    print(
                                        Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                            x.get('ip')) +
                                        Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                    continue
                            except:
                                Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                                print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                    x.get('ip')) +
                                      Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                continue
                        else:
                            Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                            print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                x.get('ip')) +
                                  Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                            continue
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            Logger().info('Starting whitelisted session with {} IPs'.format(len(mylist)))
            print(Fore.LIGHTWHITE_EX + 'Running: "' + Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                  Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTCYAN_EX + 'CTRL + C' + Fore.LIGHTWHITE_EX +
                  '" to stop.' + Fore.RESET)
            try:
                while True:
                    whitelist = Whitelist(ips=mylist)
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                Logger().info('Stopped whitelisted session')
                print(
                    Fore.LIGHTWHITE_EX + 'Stopped: "' + Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                    Fore.LIGHTWHITE_EX + '"' + Fore.RESET)

        elif option == 'blacklist':
            config = data.read_file()
            blacklist = config.get('blacklist')
            mylist = []
            for x in blacklist:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            Logger().info('Starting blacklisted session with {} IPs'.format(len(mylist)))
            print(Fore.LIGHTWHITE_EX + 'Running: "' + Fore.LIGHTBLACK_EX + 'Blacklist' +
                  Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTBLACK_EX + 'CTRL + C' + Fore.LIGHTWHITE_EX +
                  '" to stop.' + Fore.RESET)
            try:
                while True:
                    blacklist = Blacklist(ips=mylist)
                    blacklist.start()
                    time.sleep(10)
                    blacklist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                Logger().info('Stopped blacklisted session')
                print(
                    Fore.LIGHTWHITE_EX + 'Stopped: "' + Fore.LIGHTBLACK_EX + 'Blacklist' +
                    Fore.LIGHTWHITE_EX + '"' + Fore.RESET)

        elif option == 'auto_whitelist':
            Logger().info('Starting auto whitelisted session')
            collector = IPCollector()
            Logger().info('Starting to collect IPs')
            collector.start()
            for i in tqdm(range(10), ascii=True, desc='Collecting session'):
                time.sleep(1)
            collector.stop()
            mylist = list(set(collector.ips))
            Logger().info('Collected {} IPs'.format(len(mylist)))
            soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            soc.connect(("8.8.8.8", 80))
            local_ip = soc.getsockname()[0]
            soc.close()
            public_ip = get_public_ip()
            if public_ip:
                mylist.append(public_ip)
            else:
                print(
                    Fore.LIGHTWHITE_EX + 'Failed to get Public IP. Running without.' + Fore.RESET)
            mylist.append(local_ip)
            config = data.read_file()
            local_list = config.get('custom_ips')
            cloud_list = config.get('friends')
            for x in local_list:
                if x.get('enabled'):
                    try:
                        ipaddress.IPv4Address(x.get('ip'))
                        mylist.append(x.get('ip'))
                    except ipaddress.AddressValueError:
                        m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$',
                                      x.get('ip'))
                        if m:
                            try:
                                ip = socket.gethostbyname(x.get('ip'))
                                try:
                                    ipaddress.IPv4Address(ip)
                                    mylist.append(ip)
                                except ipaddress.AddressValueError:
                                    Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                                    print(
                                        Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                            x.get('ip')) +
                                        Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                    continue
                            except:
                                Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                                print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                    x.get('ip')) +
                                      Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                continue
                        else:
                            Logger().warning('Not valid IP or URL: {}'.format(x.get('ip')))
                            print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                x.get('ip')) +
                                  Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                            continue
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            mylist = list(set(mylist))
            os.system('cls')
            Logger().info('Starting whitelisted session with {} IPs'.format(len(mylist)))
            print(Fore.LIGHTWHITE_EX + 'Running: "' + Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                  Fore.LIGHTWHITE_EX + '" Press "' + Fore.LIGHTCYAN_EX + 'CTRL + C' + Fore.LIGHTWHITE_EX +
                  '" to stop.' + Fore.RESET)
            try:
                while True:
                    whitelist = Whitelist(ips=mylist)
                    whitelist.start()
                    time.sleep(10)
                    whitelist.stop()
                    time.sleep(15)
            except KeyboardInterrupt:
                Logger().info('Stopping whitelisted session')
                print(
                    Fore.LIGHTWHITE_EX + 'Stopped: "' + Fore.LIGHTCYAN_EX + 'Whitelisted session' +
                    Fore.LIGHTWHITE_EX + '"' + Fore.RESET)

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
                                print(Fore.LIGHTWHITE_EX + 'No friends' + Fore.RESET)
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
                                    print(Fore.LIGHTWHITE_EX + 'No friends' + Fore.RESET)
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
                                print(Fore.LIGHTWHITE_EX + 'No ips' + Fore.RESET)
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
                                    print(Fore.LIGHTWHITE_EX + 'No friends' + Fore.RESET)
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
                                print(Fore.LIGHTWHITE_EX + 'No friends' + Fore.RESET)
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
                                    print(Fore.LIGHTWHITE_EX + 'Cloud service down' + Fore.RESET)
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
                                            print(Fore.LIGHTWHITE_EX + 'None' + Fore.RESET)
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
                                                print(Fore.LIGHTWHITE_EX + 'Revoked' + Fore.RESET)
                                            else:
                                                print(Fore.LIGHTWHITE_EX + '{}'.format(msg.get('error')) + Fore.RESET)

                                elif answer['option'] == 'request':
                                    # My friends who I don't have perms from
                                    os.system('cls')
                                    while True:
                                        code, friends = conn.get_all()
                                        d = []
                                        if len(friends.get('friends')) <= 0:
                                            print(Fore.LIGHTWHITE_EX + 'No friends' + Fore.RESET)
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
                                                print(Fore.LIGHTWHITE_EX + 'Request sent' + Fore.RESET)
                                            else:
                                                print(Fore.LIGHTWHITE_EX + '{}'.format(msg.get('error')) + Fore.RESET)

                                elif answer['option'] == 'pending':
                                    # friends who requested permission from me
                                    os.system('cls')
                                    while True:
                                        code, friends = conn.get_pending()
                                        d = []
                                        if len(friends.get('pending')) <= 0:
                                            print(Fore.LIGHTWHITE_EX + 'None' + Fore.RESET)
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
                                                print(Fore.LIGHTWHITE_EX + 'Accepted' + Fore.RESET)
                                            else:
                                                print(Fore.LIGHTWHITE_EX + '{}'.format(msg.get('error')) + Fore.RESET)

                                        elif answer['option'] == 'decline':
                                            code, msg = conn.revoke(name)
                                            if code == 200:
                                                print(Fore.LIGHTWHITE_EX + 'Request declined' + Fore.RESET)
                                            else:
                                                print(Fore.LIGHTWHITE_EX + '{}'.format(msg.get('error')) + Fore.RESET)

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
                print(Fore.LIGHTWHITE_EX + 'None' + Fore.RESET)
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
            print(Fore.LIGHTWHITE_EX + 'Running: "' + Fore.LIGHTBLACK_EX + 'Blacklist' +
                  Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
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
                print(
                    Fore.LIGHTWHITE_EX + 'Failed to get Public IP. Running without.' + Fore.RESET)
            for x in local_list:
                if x.get('enabled'):
                    try:
                        ipaddress.IPv4Address(x.get('ip'))
                        mylist.append(x.get('ip'))
                    except ipaddress.AddressValueError:
                        m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$',
                                      x.get('ip'))
                        if m:
                            try:
                                ip = socket.gethostbyname(x.get('ip'))
                                try:
                                    ipaddress.IPv4Address(ip)
                                    mylist.append(ip)
                                except ipaddress.AddressValueError:
                                    print(
                                        Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                            x.get('ip')) +
                                        Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                    pass
                            except:
                                print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                    x.get('ip')) +
                                      Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                                pass
                        else:
                            print(Fore.LIGHTWHITE_EX + 'Not valid IP or URL: "' + Fore.LIGHTCYAN_EX + '{}'.format(
                                x.get('ip')) +
                                  Fore.LIGHTWHITE_EX + '"' + Fore.RESET)
                            pass
            for x in cloud_list:
                if x.get('enabled'):
                    mylist.append(x.get('ip'))
            print(Fore.LIGHTWHITE_EX + 'Kicking unknowns' + Fore.RESET)
            time.sleep(2)
            whitelist = Whitelist(ips=mylist)
            whitelist.start()
            time.sleep(10)
            whitelist.stop()
            continue

        elif option == 'new':
            print(Fore.LIGHTWHITE_EX + 'Creating new session' + Fore.RESET)
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
            print(Fore.LIGHTWHITE_EX + 'New token: "' + Fore.LIGHTCYAN_EX + answer[
                'token'] + Fore.LIGHTWHITE_EX + '"' + Fore.RESET)

        elif option == 'support_zip':
            os.system('cls')
            config = data.read_file()
            print(Fore.LIGHTWHITE_EX + 'NOTICE: This program will now log all udp traffic on port 6672 for 1 minute. '
                                       'Only run this if you are okey with that.' + Fore.RESET)
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
                dir_path = os.path.dirname(os.path.realpath(sys.executable))
                local_list = config.get('custom_ips')
                cloud_list = config.get('friends')
                mylist = []
                for x in local_list:
                    if x.get('enabled'):
                        try:
                            ipaddress.IPv4Address(x.get('ip'))
                            mylist.append(x.get('ip'))
                        except ipaddress.AddressValueError:
                            m = re.search('^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$',
                                          x.get('ip'))
                            if m:
                                try:
                                    ip = socket.gethostbyname(x.get('ip'))
                                    try:
                                        ipaddress.IPv4Address(ip)
                                        mylist.append(ip)
                                    except ipaddress.AddressValueError:
                                        continue
                                except:
                                    continue
                            else:
                                continue
                for x in cloud_list:
                    if x.get('enabled'):
                        mylist.append(x.get('ip'))
                debugger = Debugger(mylist, dir_path)
                debugger.start()
                for i in tqdm(range(60), ascii=True, desc='Collecting Requests'):
                    time.sleep(1)
                debugger.stop()
                time.sleep(1)
                print(Fore.LIGHTWHITE_EX + 'Collecting data' + Fore.RESET)
                customlist = config.get('custom_ips')
                cloudlist = config.get('friends')
                token = config.get('token')
                print(Fore.LIGHTWHITE_EX + 'Checking connections' + Fore.RESET)
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

                print(Fore.LIGHTWHITE_EX + 'Writing data' + Fore.RESET)
                with open("datacheck.json", "w+") as datafile:
                    json.dump(datas, datafile, indent=2)
                print(Fore.LIGHTWHITE_EX + 'Packing debug request' + Fore.RESET)
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
                print(Fore.LIGHTWHITE_EX + 'Finished' + Fore.RESET)
                compressed.close()
                continue
            else:
                print(Fore.LIGHTWHITE_EX + 'Declined' + Fore.RESET)
                continue
        elif option == 'quit':
            if pydivert.WinDivert.is_registered():
                pydivert.WinDivert.unregister()
            sys.exit(0)


if __name__ == '__main__':
    freeze_support()
    os.system('cls')
    Logger().info('Init')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(Fore.LIGHTWHITE_EX + 'Please start as administrator' + Fore.RESET)
        Logger().info('Started without admin')
        input('Press enter to exit.')
        sys.exit()
    Logger().info('Booting up')
    print(Fore.LIGHTWHITE_EX + 'Booting up...' + Fore.RESET)
    if not pydivert.WinDivert.is_registered():
        pydivert.WinDivert.register()
    ctypes.windll.kernel32.SetConsoleTitleW('Guardian {}'.format(version))
    conn = networkmanager.Cloud('')
    print(Fore.LIGHTWHITE_EX + 'Checking connections.' + Fore.RESET)
    if conn.check_connection():
        code, cversion = conn.version()
        if code == 200:
            if cversion.get('version'):
                if StrictVersion(cversion.get('version')) > StrictVersion(version):
                    os.system('cls')
                    print(Fore.LIGHTWHITE_EX + 'An update was found.' + Fore.RESET)
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
                print(Fore.LIGHTWHITE_EX + 'Starting IP syncer.' + Fore.RESET)
    while True:
        try:
            main()
        except KeyboardInterrupt:
            continue
