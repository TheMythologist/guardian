import multiprocessing
import pydivert
import time
import re
import logging
from network import networkmanager


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
        Logger().info('Dispatched whitelist blocker process')

    def stop(self):
        self.process.terminate()
        Logger().info('Terminated whitelist blocker process')

    def run(self):
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        try:
            with pydivert.WinDivert("(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip") as w:
                for packet in w:
                    ip = packet.ip.src_addr
                    temp = packet.ip.dst_addr
                    if re.search('^185\.56\.(64|65|67)\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$',
                                 ip):
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
        Logger().info('Dispatched blacklist blocker process')

    def stop(self):
        self.process.terminate()
        Logger().info('Terminated blacklist blocker process')

    def run(self):
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        try:
            with pydivert.WinDivert("(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip") as w:
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
                    try:
                        conn.set_ip()
                    except:
                        Logger().warning('Failed to update cloud IP')
                time.sleep(300)
            except KeyboardInterrupt:
                pass


class Debugger(object):
    def __init__(self, ips, dir_path):
        self.ips = ips
        self.dir_path = dir_path
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True

    def start(self):
        self.process.start()

    def stop(self):
        self.process.terminate()

    def run(self):
        FORMAT = '%(asctime)s|%(levelname)s: %(message)s'
        logging.basicConfig(format=FORMAT, filename=self.dir_path + '\debugger.log',
                            filemode='a+', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
        logger = logging.getLogger('debugger')
        logger.debug('Started debugging')
        with pydivert.WinDivert("(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip") as w:
            for packet in w:
                dst = packet.ip.dst_addr
                src = packet.ip.src_addr
                reserved = False
                whitelisted = False
                ipfilter = '^185\.56\.(64|65|67)\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$'
                if re.search(ipfilter, dst) or re.search(ipfilter, src):
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
                logger.debug(log)
                w.send(packet)


class IPCollector(object):
    def __init__(self):
        self.process = multiprocessing.Process(target=self.run, args=())
        self.process.daemon = True
        self.ips = multiprocessing.Manager().list()

    def start(self):
        self.process.start()
        Logger().info('Dispatched ipcollector process')

    def stop(self):
        self.process.terminate()
        Logger().info('Terminated ipcollector process')
        Logger().info('Collected a total of {} IPs'.format(len(self.ips)))

    def run(self):
        with pydivert.WinDivert("(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip") as w:
            for packet in w:
                dst = packet.ip.dst_addr
                src = packet.ip.src_addr

                if packet.is_inbound:
                    self.ips.append(src)
                else:
                    self.ips.append(dst)
                w.send(packet)
