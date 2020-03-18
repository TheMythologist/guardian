import multiprocessing
import pydivert
import time
import re
import logging
from network import networkmanager

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
                    temp = packet.ip.dst_addr
                    if ipfilter.match(ip):
                        w.send(packet)
                    elif ip in self.ips:
                        w.send(packet)
        except KeyboardInterrupt:
            pass


class Blacklist(object):
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
                    temp = packet.ip.dst_addr
                    if ip not in self.ips:
                        w.send(packet)
        except KeyboardInterrupt:
            pass


class IPSyncer(object):
    def __init__(self, token):
        self.token = token
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True

    def start(self):
        self.process.start()

    def stop(self):
        self.process.terminate()

    def run(self):
        while True:
            try:
                conn = networkmanager.Cloud(self.token)
                if conn.check_token():
                    if not conn.set_ip():
                        logger.warning('Failed to update cloud IP')
                time.sleep(300)
            except KeyboardInterrupt:
                pass


class Debugger(object):
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
