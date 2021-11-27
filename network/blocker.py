import multiprocessing
import pydivert
import re
import logging
import data
from network import networkmanager
from app import IPValidator
from questionary import ValidationError

from secret import my_local_ip  # I've hidden my actual local IP in a file that won't be publicly shared.
# This "secret" module does not exist anywhere, I'll make sure this is all cleaned up before the final release.

debug_logger = logging.getLogger('debugger')
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler('debugger.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s|%(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    debug_logger.addHandler(fh)
"""
It appears that there is *ONE* more problem we may need to take care of which was missed during testing of the prototype.
Apparently, it's not only R* tunnels, but also client tunnels! If the circumstances are right, then it turns out that
people in your session can also tunnel players if they could not connect to you directly. Such is the joy of P2P
gaming.

This conundrum could be easily solved with packet inspection but I'm going go back on my previous words and try to
solve this by filtering some outbound packets, as it's the only solution I can think of.

My idea is that if we receive a matchmaking request (or what could be a matchmaking request), then we will temporarily
drop responses from us to any other client in the session. This, again, will have to be guessed from the payload size.
Currently, I have no idea whether the responses to matchmaking requests are unique enough to be blocked without risking
dropping other game traffic from someone who is actually in the session.

It's possible that this behaviour can be mitigated by making the whitelist filter "air-tight" as there was a bug in the
official build which was leaking packets. However, if this bug is reported significantly in testing then I'll go ahead
and develop my theoretical solution.
"""


"""
The main flaw in Guardian lied here, in the reserved IP range. I believe this is the R* / T2 IP space, right?
In the current public build, any packet from these IPs is allowed, but we can no longer do this. We have to block
tunnelled connections which may come from this IP range, while still allowing certain services like the
session heartbeat and matchmaking requests.

Currently, my proof-of-concept does not discern whether a heartbeat has come from a R* / T2 IP as I have not been able
to confirm if that actually is the case. Ideally, ipfilter should be a range of all IPs that can send heartbeats
and / or matchmaking requests, and so the checks for packet sizes will be done only if the packet has come from an IP
in the ipfilter range.

So, ipfilter's usage has been removed from the Whitelist class. I didn't completely remove it because I think it would
still be useful to compare how the new rules can drop tunnels while still letting heartbeats and matchmaking through.
"""
ipfilter = re.compile(r'^(185\.56\.6[4-7]\.\d{1,3})$')
logger = logging.getLogger('guardian')
# packetfilter = "(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip"

"""
I decided to filter only on packets inbound to 6672 because most of the new filtering logic only checks inbound packets,
and I don't think it makes much sense to add extra load by checking outbound packets when we're not doing
anything interesting with them at the moment. I also found the packet payload sizes to be more consistent when coming
from R*-owned resources instead of looking at the responses to those requests.
I also believe that strictly filtering on inbound helps the game remain unaware that packets are being filtered and
this might mean that the game will probably behave in a more consistent manner.
(If the game was aware packets weren't reaching clients, it may change its' behaviour)

NOTE: If R* ever updates Online to support IPv6, then "and ip" should be removed from packetfilter,
      and parts of the filter logic (in the Whitelist class) that use the packet.ip attribute should be changed.
"""
packetfilter = "(udp.DstPort == 6672 and udp.PayloadLength > 0) and ip"

"""
Based on network observation, the payload sizes of packets which are probably some sort of heartbeat (and therefore
should be let through so the session stays online), or a matchmaking request (and therefore should be let through so we
can see who's attempting to connect to us).

Interesting note: All the matchmaker requests have payload sizes that may be 16 bytes apart.
"""
heartbeat_sizes = {12, 18}  # sets allow O(1) lookup
matchmaking_sizes = {245, 261, 277, 293}  # probably a player looking to join the session.

"""
Matchmaking response sizes might be: 45, 125, 205?
The size 45 payload definitely cannot be blocked as it pops up frequently in normal gameplay.
It appears that the 125 and 205 packets also pop up from time to time.
The first *two* packets sent to a client joining do appear to be size 125 and 205, though. Hmmm...
So the initial join response appears to be 125, 205, 45, 317, 493?

Looks like blocking 205 inbound is our best bet. 493 outbound is also a possibility but probably has a chance of
accidentally dropping the client non-tunnels.

After I wrote these comments it was discovered that Guardian wasn't filtering packets all the time. This bug has since
been fixed and hopefully will also mean these "client tunnels" are now no longer an issue. Leaving these notes in just
in case they're useful later on.
"""


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
        print("ips: " + str(self.ips))
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        try:
            with pydivert.WinDivert(packetfilter) as w:
                for packet in w:
                    ip = packet.ip.src_addr
                    size = len(packet.payload)  # the size of the payload. used to guess packet's behaviour / "intent"
                    # The below rule had to go so we can block session tunnels.
                    """if ipfilter.match(ip):
                        w.send(packet)"""
                    """ Note that my_local_ip is in a .gitignore'd file so I don't leak it when this fork goes public
                        and people check through the commits. """
                    if ip == my_local_ip:
                        print(packet)
                    if ip in self.ips:
                        w.send(packet)
                        print("ALLOWING PACKET FROM " + packet.src_addr + ":" + str(packet.src_port) + " Len:" + str(len(packet.payload)))
                        """
                    The "special sauce" for the new filtering logic. We're using payload sizes to guess if the packet
                    has a behaviour we want to allow through.
                    """
                    elif (size in heartbeat_sizes) or (size in matchmaking_sizes):
                        w.send(packet)
                        print("ALLOWING PACKET FROM " + packet.src_addr + ":" + str(packet.src_port) + " Len:" + str(len(packet.payload)))
                    else:
                        print("DROPPING PACKET FROM " + packet.src_addr + ":" + str(packet.src_port) + " Len:" + str(len(packet.payload)))

        except KeyboardInterrupt:
            """ This never hits, but the override is still necessary to stop the program from quitting on CTRL + C. """
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
                size = len(packet.payload)
                whitelisted = False
                reserved_allow = False  # Packet from a reserved IP was allowed.
                reserved_block = False  # Packet from a reserved IP was blocked.
                service = False  # Packet allowed because it could be heartbeat / matchmaker but not from a reserved IP.
                if ipfilter.match(dst) or ipfilter.match(src):
                    if (size in heartbeat_sizes) or (size in matchmaking_sizes):
                        reserved_allow = True
                    else:
                        reserved_block = True  # Came from a "reserved" IP but was blocked under the new rules.
                elif dst in self.ips or src in self.ips:
                    whitelisted = True
                elif (size in heartbeat_sizes) or (size in matchmaking_sizes):
                    service = True  # Was allowed because it may be service-related, but wasn't from a reserved IP.

                if whitelisted:
                    filler = 'Whitelist'
                elif reserved_allow:
                    filler = 'Reserved (Allowed)'
                elif reserved_block:
                    filler = 'Reserved (Blocked)'
                elif service:
                    filler = 'Service (Allowed)'
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
