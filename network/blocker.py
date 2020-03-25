import multiprocessing
import pydivert
import re
import logging
import data
from network import networkmanager
from app import IPValidator
from questionary import ValidationError

debug_logger = logging.getLogger('debugger')
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler('debugger.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s|%(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    debug_logger.addHandler(fh)

ipfilter = re.compile(r'^(185\.56\.6[4-7]\.\d{1,3})$')
logger = logging.getLogger('guardian')
packetfilter = "(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip"


class Whitelist(object):
    """
    Packet filter that will allow packets from with source ip present on ips list
    """
    def __init__(self, ips):
        """
        :param list ips:
        """
        self.ips = ips
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True

    def start(self):
        self.process.start()
        logger.info('Dispatched whitelist blocker process')

    def stop(self):
        self.process.terminate()
        logger.info('Terminated whitelist blocker process')

    def run(self):
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        try:
            with pydivert.WinDivert(packetfilter) as w:
                for packet in w:
                    ip = packet.ip.src_addr
                    if ipfilter.match(ip):
                        w.send(packet)
                    elif ip in self.ips:
                        w.send(packet)
        except KeyboardInterrupt:
            pass


class Blacklist(object):
    """
    Packet filter that will block packets from with source ip present on ips list
    """
    def __init__(self, ips):
        """
        :param list ips:
        """
        self.ips = ips
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True

    def start(self):
        self.process.start()
        logger.info('Dispatched blacklist blocker process')

    def stop(self):
        self.process.terminate()
        logger.info('Terminated blacklist blocker process')

    def run(self):
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        try:
            with pydivert.WinDivert(packetfilter) as w:
                for packet in w:
                    ip = packet.ip.src_addr
                    if ip not in self.ips:
                        w.send(packet)
        except KeyboardInterrupt:
            pass


class IPSyncer(object):
    """
    Looper thread to update user ip to the cloud and domain based list items ips
    """
    def __init__(self, token):
        """
        :param token: Cloud api token
        """
        self.token = token
        self.process = multiprocessing.Process(target=self.run, args=())
        self.exit = multiprocessing.Event()

    def start(self):
        if self.token:
            self.process.start()
        else:
            logger.warning("Tried to start IPSyncer without token")

    def stop(self):
        if self.token:
            self.exit.set()
            self.process.join()

    def run(self):
        while not self.exit.is_set():
            try:
                conn = networkmanager.Cloud(self.token)
                if conn.check_token():
                    if not conn.set_ip():
                        logger.warning('Failed to update cloud IP')
                config = data.ConfigData(data.file_name)
                lists = [data.CustomList('blacklist'), data.CustomList('custom_ips')]
                for l in lists:
                    outdated = []
                    new = {}
                    for ip, item in l:
                        domain = item.get('value')
                        if domain:
                            try:
                                ip_calc = IPValidator.validate_get(domain)
                                if ip != ip_calc:
                                    outdated.append(ip)
                                    new[ip_calc] = item
                            except ValidationError as e:
                                logger.warning(e.message)
                                continue
                    for old, new, item in zip(outdated, new.keys(), new.values()):
                        l.delete(old)
                        l.add(new, item)
                        logger.info("Updated {} ip".format(item.get('name', 'Unknown')))

                config.save()
                self.exit.wait(300)
            except KeyboardInterrupt:
                pass


class Debugger(object):
    """
    Thread to create a log of the ips matching the packet filter
    """
    def __init__(self, ips):
        self.ips = ips
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True

    def start(self):
        self.process.start()

    def stop(self):
        self.process.terminate()

    def run(self):
        debug_logger.debug('Started debugging')
        with pydivert.WinDivert(packetfilter) as w:
            for packet in w:
                dst = packet.ip.dst_addr
                src = packet.ip.src_addr
                reserved = False
                whitelisted = False
                if ipfilter.match(dst) or ipfilter.match(src):
                    reserved = True
                elif dst in self.ips or src in self.ips:
                    whitelisted = True

                if reserved:
                    filler = 'Reserved'
                elif whitelisted:
                    filler = 'Whitelist'
                else:
                    filler = 'Blocked'

                if packet.is_inbound:
                    log = '[{}] {}:{} --> {}:{}'.format(filler, src, packet.src_port, dst, packet.dst_port)
                else:
                    log = '[{}] {}:{} <-- {}:{}'.format(filler, src, packet.src_port, dst, packet.dst_port)
                debug_logger.debug(log)
                w.send(packet)


class IPCollector(object):
    """
    Thread to store all the ip addresses matching the packet filter
    """
    def __init__(self):
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True
        self.ips = multiprocessing.Manager().list()

    def start(self):
        self.process.start()
        logger.info('Dispatched ipcollector process')

    def stop(self):
        self.process.terminate()
        logger.info('Terminated ipcollector process')
        logger.info('Collected a total of {} IPs'.format(len(self.ips)))

    def run(self):
        with pydivert.WinDivert(packetfilter) as w:
            for packet in w:
                dst = packet.ip.dst_addr
                src = packet.ip.src_addr

                if packet.is_inbound:
                    self.ips.append(src)
                else:
                    self.ips.append(dst)
                w.send(packet)
