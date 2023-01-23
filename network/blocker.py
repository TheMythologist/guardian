import contextlib
import logging
import multiprocessing
import re
from abc import abstractmethod, ABC

import pydivert
from questionary import ValidationError

import data
from app import IPValidator
from network import networkmanager, sessioninfo
from util.DynamicBlacklist import ip_in_cidr_block_set

debug_logger = logging.getLogger("debugger")
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler("debugger.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s|%(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    debug_logger.addHandler(fh)

# It appears that there is *ONE* more problem we may need to take care of which was missed during testing of the prototype.
# Apparently, it's not only R* tunnels, but also client tunnels! If the circumstances are right, then it turns out that
# people in your session can also tunnel players if they could not connect to you directly. Such is the joy of P2P
# gaming.

# This conundrum could be easily solved with packet inspection but I'm going go back on my previous words and try to
# solve this by filtering some outbound packets, as it's the only solution I can think of.

# My idea is that if we receive a matchmaking request (or what could be a matchmaking request), then we will temporarily
# drop responses from us to any other client in the session. This, again, will have to be guessed from the payload size.
# Currently, I have no idea whether the responses to matchmaking requests are unique enough to be blocked without risking
# dropping other game traffic from someone who is actually in the session.

# It's possible that this behaviour can be mitigated by making the whitelist filter "air-tight" as there was a bug in the
# official build which was leaking packets. However, if this bug is reported significantly in testing then I'll go ahead
# and develop my theoretical solution.

# The main flaw in Guardian lied here, in the reserved IP range. I believe this is the R* / T2 IP space, right?
# In the current public build, any packet from these IPs is allowed, but we can no longer do this. We have to block
# tunnelled connections which may come from this IP range, while still allowing certain services like the
# session heartbeat and matchmaking requests.

# Currently, my proof-of-concept does not discern whether a heartbeat has come from a R* / T2 IP as I have not been able
# to confirm if that actually is the case. Ideally, ipfilter should be a range of all IPs that can send heartbeats
# and / or matchmaking requests, and so the checks for packet sizes will be done only if the packet has come from an IP
# in the ipfilter range.

# So, ipfilter's usage has been removed from the Whitelist class. I didn't completely remove it because I think it would
# still be useful to compare how the new rules can drop tunnels while still letting heartbeats and matchmaking through.

ipfilter = re.compile(r"^(185\.56\.6[4-7]\.\d{1,3})$")
logger = logging.getLogger("guardian")

# I decided to filter only on packets inbound to 6672 because most of the new filtering logic only checks inbound packets,
# and I don't think it makes much sense to add extra load by checking outbound packets when we're not doing
# anything interesting with them at the moment. I also found the packet payload sizes to be more consistent when coming
# from R*-owned resources instead of looking at the responses to those requests.
# I also believe that strictly filtering on inbound helps the game remain unaware that packets are being filtered and
# this might mean that the game will probably behave in a more consistent manner.
# (If the game was aware packets weren't reaching clients, it may change its behaviour)

# NOTE: If R* ever updates Online to support IPv6, then "and ip" should be removed from packetfilter,
# and parts of the filter logic (in the Whitelist class) that use the packet.ip attribute should be changed.

# packetfilter = "(udp.SrcPort == 6672 or udp.DstPort == 6672) and ip"
packetfilter = "(udp.DstPort == 6672 and udp.PayloadLength > 0) and ip"

# Based on network observation, the payload sizes of packets which are probably some sort of heartbeat (and therefore
# should be let through so the session stays online), or a matchmaking request (and therefore should be let through so we
# can see who's attempting to connect to us).

# Interesting note: All the matchmaker requests have payload sizes that may be 16 bytes apart.

heartbeat_sizes = {12, 18}
matchmaking_sizes = {
    245,
    261,
    277,
    293,
}  # probably a player looking to join the session.

known_sizes = heartbeat_sizes.union(matchmaking_sizes)

# Matchmaking response sizes might be: 45, 125, 205?
# The size 45 payload definitely cannot be blocked as it pops up frequently in normal gameplay.
# It appears that the 125 and 205 packets also pop up from time to time.
# The first *two* packets sent to a client joining do appear to be size 125 and 205, though. Hmmm...
# So the initial join response appears to be 125, 205, 45, 317, 493?

# Looks like blocking 205 inbound is our best bet. 493 outbound is also a possibility but probably has a chance of
# accidentally dropping the client non-tunnels.

# After I wrote these comments it was discovered that Guardian wasn't filtering packets all the time. This bug has since
# been fixed and hopefully will also mean these "client tunnels" are now no longer an issue. Leaving these notes in just
# in case they're useful later on.


class AbstractPacketFilter(ABC):
    # TODO: Type safety -> should ips be `list` or `set`?
    def __init__(self, ips, session_info=None, debug=False):
        self.ips = ips
        self.process = multiprocessing.Process(target=self.run)
        self.process.daemon = True
        self.session_info = session_info
        self.debug_print_decisions = debug
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()

    def start(self):
        self.process.start()
        logger.info("Dispatched %s blocker process", self.__class__.__name__)

    def stop(self):
        self.process.terminate()
        logger.info("Terminated %s blocker process", self.__class__.__name__)

    @abstractmethod
    def is_packet_allowed(self, packet):
        pass

    def run(self):
        logger.info("ips: %s", self.ips)

        # To allow termination via CTRL + C
        with contextlib.suppress(KeyboardInterrupt):
            with pydivert.WinDivert(packetfilter) as w:
                for packet in w:
                    decision = self.is_packet_allowed(packet)
                    if decision:
                        w.send(packet)

                    if self.session_info is not None:
                        self.session_info.add_packet(
                            sessioninfo.safe_pickle_packet(packet), allowed=decision
                        )

                    if self.debug_print_decisions:
                        print(self.construct_debug_packet_info(packet, decision))

    @staticmethod
    def construct_debug_packet_info(packet, decision=None):
        prefix = "" if decision is None else ("ALLOWING" if decision else "DROPPING")

        return f"{prefix} PACKET FROM {packet.src_addr}:{packet.src_port}  Len: {len(packet.payload)}"


class Whitelist(AbstractPacketFilter):
    """
    Packet filter that will allow packets from with source ip present on ips list
    """

    def __init__(self, ips, session_info=None, debug=False):
        super().__init__(ips, session_info, debug)

    def is_packet_allowed(self, packet):
        ip = packet.ip.src_addr
        size = len(packet.payload)

        # The "special sauce" for the new filtering logic. We're using payload sizes to guess if the packet
        # has a behaviour we want to allow through.
        if ip in self.ips or size in known_sizes:
            return True


class Blacklist(AbstractPacketFilter):
    """
    Packet filter that will block packets from with source ip present on ips list
    """

    def __init__(
        self, ips, blocks=None, known_allowed=None, session_info=None, debug=False
    ):
        super().__init__(ips, session_info, debug)

        if blocks is None:
            blocks = set()
        if known_allowed is None:
            known_allowed = set()

        self.ip_blocks = blocks  # set of CIDR blocks
        self.known_allowed = known_allowed  # IPs which are known to not be in blocks

    def is_packet_allowed(self, packet):
        ip = packet.ip.src_addr
        size = len(packet.payload)

        if ip in self.known_allowed or size in known_sizes:
            return True
        elif ip not in self.ips:
            # If it's not directly blacklisted it might be in a blacklisted range
            if ip_in_cidr_block_set(ip, self.ip_blocks):
                # It was in a blacklisted range, add this to the standard list
                self.ips.add(ip)
                return False
            else:
                # If not then it's definitely allowed, remember this for next time
                self.known_allowed.add(ip)
                return True
        else:
            return False


class Locked(AbstractPacketFilter):
    """
    Packet filter to block any new requests to join the session.
    """

    def is_packet_allowed(self, packet):
        size = len(packet.payload)

        # No new matchmaking requests allowed.
        # Seems a bit overkill (and perhaps reckless) to always block these payload sizes but my packet
        # captures show that these payload sizes don't occur in any regular game traffic so...
        return size not in matchmaking_sizes


class IPSyncer:
    """
    Looper thread to update user ip to the cloud and domain based list items ips
    """

    def __init__(self, token):
        """
        :param token: Cloud api token
        """
        self.token = token
        self.process = multiprocessing.Process(target=self.run)
        self.exit = multiprocessing.Event()

    def start(self):
        if self.token:
            self.process.start()
        else:
            logger.warning("IPSyncer cannot start without token")

    def stop(self):
        if self.token:
            self.exit.set()
            self.process.join()

    def run(self):
        while not self.exit.is_set():
            with contextlib.suppress(KeyboardInterrupt):
                conn = networkmanager.Cloud(self.token)
                if conn.check_token() and not conn.set_ip():
                    logger.warning("Failed to update cloud IP")
                config = data.ConfigData(data.file_name)
                lists = [data.CustomList("blacklist"), data.CustomList("custom_ips")]
                for custom_list in lists:
                    outdated = []
                    new = {}
                    for ip, item in custom_list:
                        domain = item.get("value")
                        if domain:
                            try:
                                ip_calc = IPValidator.validate_get(domain)
                                if ip != ip_calc:
                                    outdated.append(ip)
                                    new[ip_calc] = item
                            except ValidationError as e:
                                logger.warning(e.message)
                    for old, new, item in zip(outdated, new.keys(), new.values()):
                        custom_list.delete(old)
                        custom_list.add(new, item)
                        logger.info("Updated %s ip", item.get("name", "Unknown"))

                config.save()
                self.exit.wait(300)


class Debugger:
    """
    Thread to create a log of the ips matching the packet filter
    """

    def __init__(self, ips):
        self.ips = ips
        self.process = multiprocessing.Process(target=self.run)
        self.process.daemon = True

    def start(self):
        self.process.start()

    def stop(self):
        self.process.terminate()

    def run(self):
        debug_logger.debug("Started debugging")
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
                    if size in known_sizes:
                        reserved_allow = True
                    else:
                        reserved_block = True  # Came from a "reserved" IP but was blocked under the new rules.
                elif dst in self.ips or src in self.ips:
                    whitelisted = True
                elif size in known_sizes:
                    service = True  # Was allowed because it may be service-related, but wasn't from a reserved IP.

                if whitelisted:
                    filler = "Whitelist"
                elif reserved_allow:
                    filler = "Reserved (Allowed)"
                elif reserved_block:
                    filler = "Reserved (Blocked)"
                elif service:
                    filler = "Service (Allowed)"
                else:
                    filler = "Blocked"

                if packet.is_inbound:
                    log = f"[{filler}] {src}:{packet.src_port} --> {dst}:{packet.dst_port}"
                else:
                    log = f"[{filler}] {src}:{packet.src_port} <-- {dst}:{packet.dst_port}"
                debug_logger.debug(log)
                w.send(packet)


# Okay, so there's a couple of changes that need to be done to fix auto-whitelisting.

# The main flaw is that this IPCollector has a chance of collecting IPs that are responsible for R* Services
# (and can i.e. be used for tunnelling).
# When you're in a session, a R* Service will "ping" your session / check for a "heartbeat". If your session is pinged
# while the IPCollector is running, the IPCollector will add the source of that ping to the whitelist.

# This wasn't a problem before Online 1.54 because these services weren't used for tunneling connections. But, now, if
# a player joining the session cannot connect to you directly, these IPs can be used for R* Services *can* be used for
# tunnelled session traffic. As the IPCollector has added these R* Service IPs to the whitelist, tunnelled connections are
# now also whitelisted, which obviously breaks session security.

# The first fix is to adjust the rules / "reasons" the IPCollector may add an IP to the auto-whitelist.
# Because the new filters only filter inbound traffic, I have decided to only add an IP to the auto-whitelist if:
#   - the packet is inbound
#   - the packet does not contain a payload size equal to a heartbeat
#   - the packet does not contain a payload size equal to a matchmaking request

# There is one more check we need to perform, which will be done *after* the IP collector has run, mainly due to the extra
# complexity required to perform it.
# My research indicates that R* uses Microsoft Azure Cloud for most of their R* Services. Microsoft frequently publishes
# their IP ranges used for cloud activity. As a last safe-guarding step, we should acquire these IP ranges and ensure that
# collected IPs do not correspond to any cloud traffic.

# If the new version of the IPCollector has saved an IP address used by Azure, this almost certainly guarantees that
# someone is already being tunnelled through a R* Service (as using Azure for VPNs is incredibly rare), and we will need
# to display a warning that these players must be dropped from the session for security to remain.

# There are some extra heuristics we could also add to the IPCollector, such as actually noting any IPs that might be
# R* Services by checking their payload sizes, running the auto-whitelist service for a whole 60 seconds (!), and also
# only adding IPs which have sent a certain threshold of packets during the IP collection phase. (When in a session, you
# send a *significant* amount of packets between clients, compared to only a handful of packets for other misc. activity.)


class IPCollector:
    """
    Thread to store all the ip addresses matching the packet filter
    """

    def __init__(self, packet_count_min_threshold=1):
        self.process = multiprocessing.Process(target=self.run)
        self.process.daemon = True
        self.ips = multiprocessing.Manager().list()
        self.seen_ips = (
            multiprocessing.Manager().dict()
        )  # key is IP address, value is packets seen
        self.min_packets = packet_count_min_threshold  # minimum amount of packets required to be seen to be added
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()

        # self.ips.append("20.40.183.2")      # DEBUG, forcing an Azure IP to be included
        # self.ips.append("192.81.240.99")    # DEBUG, forcing a T2 US IP to be included

    def add_seen_ip(self, ip):
        """
        Keeps a "counter" of how many packets have been seen from this IP.
        """
        self.seen_ips[ip] = self.seen_ips.get(ip, 0) + 1

    def save_ips(self):
        """
        Saves any IP that has been seen at least self.min_packets times.
        """
        for ip in self.seen_ips:
            if self.seen_ips[ip] >= self.min_packets:
                self.ips.append(ip)

    def start(self):
        self.process.start()
        logger.info("Dispatched IPCollector process")

    def stop(self):
        self.process.terminate()
        logger.info("Terminated IPCollector process")
        self.save_ips()
        logger.info("Collected a total of %d IPs", len(self.ips))

    def run(self):
        # TODO: Can you run PyDivert in sniff mode, instead of having to run a filter?
        # TODO: We could also actually check to see *when* the last packet was seen from that IP.
        with contextlib.suppress(KeyboardInterrupt):
            with pydivert.WinDivert(packetfilter) as w:
                for packet in w:
                    size = len(packet.payload)

                    if packet.is_inbound and size not in known_sizes:
                        src = packet.ip.src_addr
                        self.add_seen_ip(src)
                    w.send(packet)
