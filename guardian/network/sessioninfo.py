from typing import Optional

from pydivert import packet

from network.connectionstats import ConnectionStats
from network.iptag import IPTag

# Ok so now that we've finally figured out most of the bugs / problems with pickling packets we can now actually start
# to curate information from packets (and perhaps even other metrics) that can be displayed. I have a couple ideas:

# Filter Processing Time: The amount of time it took to process the previous packet.
# Average Filter Processing Time: A cycling queue of 50 or 100 numbers, all containing the amount of time in seconds it
#     took to filter each packet. Would give a good idea on the additional latency introduced by the filter.

# Last IPC Overhead: The amount of time it took to pickle / pipe information across to the diagnostic process.
# Average IPC Overhead: Cycling queue of 50 or 100 numbers, same ideology as Average Filter Processing Time.

# Current Filter Load: The amount of "off-time" between filtering two different packets. I believe the calculation would
#     be (filter_processing_time) / (filter_processing_time + filter_off_time). If filter_off_time is big, the filter is
#     not under load and the resulting value is small. If filter_off_time is small, the filter is loaded and the resulting
#     value will be much closer to 1 (or 100%).
# Average Filter Load: Same as Current Filter Load, but the last 50 or 100 calculations.

# Per IP:
#     Packets Received:               Pretty obvious.
#     Bytes Received:                 Pretty obvious.
#     Packets Received per second:    Pretty obvious. Could this metric be used as a last line of defence on client tunnels?
#     Bytes Received per second:      Pretty obvious.
#     Last Seen / Last Packet Recv'd: Pretty obvious.
#     Packets Dropped:                Pretty obvious.
#     Packets Allowed:                Pretty obvious.

# Tags:   Miscellaneous information about an IP. All in text format.
#     VPN / Residential / TOR:    What "kind" of IP this is.
#     R* OFFICIAL / R* SERVICES:  If this is used by R* for their services.
#     APPROXIMATE LOCATION:       Nothing too descriptive, just the continent / nation. We don't want dox'ing.
#     MODDER / STALKER / SCRAPER: There's a chance that we can tag stalkers based on network behaviour.
#     WHITELISTED [TAG]:          This IP is whitelisted.
#     BLACKLISTED [TAG]:          This IP is blacklisted.
#     FRIEND [TAG]:               This IP belongs to a cloud-based friend.
#     UNKNOWN:                    This IP has been seen but it's behaviour is unknown.
#     CONNECTED / IN SESSION:     This IP is currently in the session.

# Overall:
#     Packets Received:
#     Packets Dropped:
#     Packets Allowed:
#     Bytes Received:
#     Bytes Dropped:
#     Bytes Allowed:

# Meta:   Relating to the processing of Diagnostics.
#     Diagnostics Queue Size:     How many packets are pending processing.
#     Average Processing Time:    Average of how long it took to process the last 50 / 100 packets.
#     Print Overhead:             How long it's taking to display content on the screen.
#     Average Print Overhead:     Same logic as all the other averaging methods.

#  ================================
#         IP       | Packets IN | Packets IN/s | Bytes IN | Bytes IN/s | Packets OUT | Packets OUT/s | Bytes OUT | Bytes OUT/s | Last Seen | # Pckts Allowed | # Pckts Dropped | Tags and Info
#  192.168.0.235   |      0     |      0.0     |     0    |     0.0    |      0      |      0.0      |     0     |     0.0     |   NEVER   |        0        |        0        |    LOCAL IP
#  172.68.2.143    |      0     |      0.0     |     0    |     0.0    |      0      |      0.0      |     0     |     0.0     |   NEVER   |        0        |        0        |    PUBLIC IP
#  255.255.255.255 |     24     |      0.0     |     0    |     0.0    |      0      |      0.0      |     0     |     0.0     |    10s    |       24        |        0        |   R* SERVICES
#  85.42.1.15      |                                                                                                                                                           |     UNKNOWN       (CRP, IT)
#  101.172.93.149  |                                                                                                                                                           |     UNKNOWN       (RES, AU)
#  1.145.210.255   |                                                                                                                                                           |     UNKNOWN       (MBL, AU)
#  66.176.75.199   |                                                                                                                                                           |   1x JOIN REQ.    (RES, US)
#                  |                                                                                                                                                           | 1x REQ. 1x CNFM.
#                  |                                                                                                                                                           |   2x JOIN CNFM.
#                  |                                                                                                                                                           |    CONNECTED      [TessioMT]
#                  |                                                                                                                                                           |   WHITELISTED     [RDS128]
#                  |                                                                                                                                                           |   BLACKLISTED     [Example]
#       TOTAL      |                                                                                                                                                           |  RUNNING FOR: 12 MINUTES

#  Avg. Filter Load: 23%      Avg. FPT: 0.39 ms      Avg. IPC: 2.31 ms      Print Time: 23 ms
#  Cur. Filter Load: <1%      Last FPT: 0.12 ms      Last IPC: 22.9 ms      Queue Size: 2
#  ================================

# Tag Priotity:   This is the order of precedence for the info tags. Lower is more important.
#  UNKNOWN
#  WHITELISTED
#  BLACKLISTED
#  xx JOIN REQ.
#  xx REQ. xx CNFM.
#  CONNECTED
#  R* SERVICES
#  LOCAL IP
#  PUBLIC IP

# Can we also add coloured rows to the list? Would be pretty pog to see rows turn green when a packet was accepted, red when a packet was rejected, etc.


class SessionInfo:
    """
    Returns human-readable strings that expose session information to the user after being supplied captured packets.

    proxy_dict: A proxy to a dictionary (for known_ips)
    proxy_list: A proxy to a list (for connection_stats)
    proxy_queue: A proxy to a Queue (for packet_queue)
    Proxies must be passed down from the parent (and will also be shared elsewhere so they can be modified).

    initial_ips: Array of IPTag that should be known before any traffic is received from those IPs.

    known_ips: Dictionary of known IPs, used to check if an IP has been seen previously.
        Value stored is the index into an array of ConnectionStats.
    connection_stats: Array of ConnectionStats, which contain the calculations and statistics of connections.
    """

    def __init__(
        self,
        proxy_dict,
        proxy_list: list[ConnectionStats],
        proxy_queue,
        initial_ips: Optional[list[IPTag]] = None,
    ) -> None:
        if initial_ips is None:
            initial_ips = []

        self.known_ips = proxy_dict
        self.connection_stats: list[ConnectionStats] = proxy_list

        for ip_tag in initial_ips:
            self.add_con_stat_from_ip_tag(ip_tag)
        # Connection stats and known IPs are now initialised.

        # This is a queue of packets pending processing. I wanted to make adding packets to SessionInfo objects as light
        # as possible because packets will come from the filtering thread and if not designed properly, would "block" the
        # entire filter for as long as it took for SessionInfo to process that packet. This could lead to in-game
        # latency at best, and possibly a program crash at worst (because the filter cannot process packets quickly
        # enough and lead to memory exhaustion).

        # So, "adding" a packet actually only puts it in this queue, and a different process will do the depletion (and
        # of course, processing) of packets in this queue.

        self.packet_queue = proxy_queue

        # self.processing_thread = Process(target=self.run, daemon=True)

    # def start(self) -> None:
    #     self.processing_thread.start()

    # def stop(self) -> None:
    #     self.processing_thread.terminate()

    def add_packet(self, packet: packet.Packet, allowed: bool) -> None:
        """
        A packet was received by the filter and is now being shared with SessionInfo.

        packet: The packet (as received by PyDivert)
        allowed: Whether the packet was allowed (true) or dropped (false).
        """
        # We cannot waste any time waiting for a spot in the queue. This function is called in the context of the
        # filtering thread and so processing will happen later (and almost certainly on a different thread).
        self.packet_queue.put((packet, allowed), block=False)

    def process_item(self, block=True) -> None:
        """
        Depletes the queue of a single packet that has been added from the filtering thread.
        Note that by default, whatever thread calls this method *will be blocked* until there is an item in the queue.
        If you don't want your thread blocked, you will need to handle Empty exceptions because the queue *will* be
        empty at some points during processing.
        """
        # If there is a packet in the queue, get it (or wait for one)
        packet, allowed = self.packet_queue.get(block)
        self.process_packet(packet, allowed)

    def process_packet(self, packet: packet.Packet, allowed) -> None:
        ip = packet.src_addr if packet.is_inbound else packet.dst_addr

        # If we're not aware of this destination, a new ConnectionStat (and conseq. IPTag) is required.
        if ip not in self.known_ips:
            # TODO: We might be able to use IP ranges to give IPs custom tags. (e.g. ROCKSTAR, UNKNOWN (USA), etc.)
            # Now that the ConnectionStat exists, we can get it
            self.add_con_stat_from_ip_tag(IPTag(ip, "UNKNOWN"))

        con_stat = self.get_con_stat_from_ip(ip)
        # Pass the packet down to ConnectionStat where metrics will be calculated
        con_stat.add_packet(packet, allowed)
        self.connection_stats[self.known_ips[ip]] = con_stat

        # Sigh. I thought that con_stat would be a shallow copy, but considering
        # connection_stats is a proxy list (doesn't exist in this process), then *of course*
        # updating con_stat here without saving / 'writing' the new state back into the proxy list wouldn't
        # actually change the data in connection_stats.

    def add_con_stat_from_ip_tag(self, ip_tag: IPTag) -> None:
        """
        Adds an IP (with tag) to connection stats.
        """
        this_ip = ip_tag.ip

        # If this IP has already been added, don't do it again.
        if this_ip not in self.known_ips:
            # Add this_ip to dictionary with value of index into
            self.known_ips[this_ip] = len(self.connection_stats)
            self.connection_stats.append(ConnectionStats(ip_tag))

    def get_con_stat_from_ip(self, ip):
        """
        Returns the connection stat object associated with this IP.

        NOTE: Will throw KeyError there is no ConnectionStat for the given ip.
        """
        return self.connection_stats[self.known_ips[ip]]


def generate_stats(connection_stats: list[ConnectionStats]) -> str:
    """
    Given a list containing connection statistics, generates a human-readable representation of those statistics.
    This function was originally the override for __str__ (so you could just call print(session_info)) but it appears a lot
    of my assumptions about programming design need to go out the window when writing multi-processing programs.
    """
    str_gen = []
    for con_stat in connection_stats:
        info = con_stat.get_info()
        info_str = "\t | ".join(
            (
                f"IP: {info['ip']}",
                f"Packets IN: {info['packets_in']}",
                f"Packets OUT: {info['packets_out']}",
                f"Last Seen: {info['last_seen']}",
                f"Allowed: {info['packets_allowed']}",
                f"Dropped: {info['packets_dropped']}",
                f"Tag: {info['tag']}",
            )
        )
        str_gen.append(info_str)
    return "\n".join(str_gen)
