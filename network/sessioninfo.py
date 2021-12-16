from multiprocessing import Manager, Process
import os

"""
Ok so now that we've finally figured out most of the bugs / problems with pickling packets we can now actually start
to curate information from packets (and perhaps even other metrics) that can be displayed. I have a couple ideas:

Filter Processing Time: The amount of time it took to process the previous packet.
Average Filter Processing Time: A cycling queue of 50 or 100 numbers, all containing the amount of time in seconds it
    took to filter each packet. Would give a good idea on the additional latency introduced by the filter.
    
Last IPC Overhead: The amount of time it took to pickle / pipe information across to the diagnostic process.
Average IPC Overhead: Cycling queue of 50 or 100 numbers, same ideology as Average Filter Processing Time.

Current Filter Load: The amount of "off-time" between filtering two different packets. I believe the calculation would
    be (filter_processing_time) / (filter_processing_time + filter_off_time). If filter_off_time is big, the filter is
    not under load and the resulting value is small. If filter_off_time is small, the filter is loaded and the resulting
    value will be much closer to 1 (or 100%).
Average Filter Load: Same as Current Filter Load, but the last 50 or 100 calculations.

Per IP:
    Packets Received:               Pretty obvious.
    Bytes Received:                 Pretty obvious.
    Packets Received per second:    Pretty obvious. Could this metric be used as a last line of defence on client tunnels?
    Bytes Received per second:      Pretty obvious.
    Last Seen / Last Packet Recv'd: Pretty obvious.
    Packets Dropped:                Pretty obvious.
    Packets Allowed:                Pretty obvious.

Tags:   Miscellaneous information about an IP. All in text format.
    VPN / Residential / TOR:    What "kind" of IP this is.
    R* OFFICIAL / R* SERVICES:  If this is used by R* for their services.
    APPROXIMATE LOCATION:       Nothing too descriptive, just the continent / nation. We don't want dox'ing.
    MODDER / STALKER / SCRAPER: There's a chance that we can tag stalkers based on network behaviour. When modders try
                                to see if you're online, there's no attempt to join. Just 205s and 45s on the game port.
    WHITELISTED [TAG]:          This IP is whitelisted.
    BLACKLISTED [TAG]:          This IP is blacklisted.
    FRIEND [TAG]:               This IP belongs to a cloud-based friend.
    UNKNOWN:                    This IP has been seen but it's behaviour is unknown.
    CONNECTED / IN SESSION:     This IP is currently in the session.
    
Overall:
    Packets Received:
    Packets Dropped:
    Packets Allowed:
    Bytes Received:
    Bytes Dropped:
    Bytes Allowed:    

Meta:   Relating to the processing of Diagnostics.
    Diagnostics Queue Size:     How many packets are pending processing.
    Average Processing Time:    Average of how long it took to process the last 50 / 100 packets.
    Print Overhead:             How long it's taking to display content on the screen.
    Average Print Overhead:     Same logic as all the other averaging methods.
"""

class MinimalPacket:

    def __init__(self, packet):
        #self.ip = packet.ip
        #self.ip.src_addr = packet.ip.src_addr

        #self.ip.raw.release()
        #self.ip.raw = bytes(self.ip.raw)
        #self.payload = bytes(packet.raw)
        self.src_addr = packet.src_addr
        self.src_port = packet.src_port
        self.dst_addr = packet.dst_addr
        self.dst_port = packet.dst_port
        self.is_inbound = packet.is_inbound
        self.is_outbound = packet.is_outbound
        self.direction = packet.direction

def safe_pickle_packet(packet):
    """
    Returns a variant of a PyDivert packet that:
    a) can be pickled (typical PyDivert packets use MemoryView which cannot be pickled)
    b) has had certain untrusted, external information redacted (code execution can occur when unpickling, i.e.
       certain externally-controllable characteristics like packet content should be removed)
    """
    """
    Delete the raw payload content. We don't need it (it's encrypted anyways) and modded clients can send raw bytes
    to other clients, including us, which could allow arbitrary code execution to occur when unpickling packet objects.
    (See https://docs.python.org/3/library/pickle.html)
    
    TODO: Investigate performance of serialization with JSON instead of pickling to improve program security.
    """
    #packet.raw.release()
    #packet.raw = None
    #packet.raw = packet.raw.tobytes()  # convert to finite array

    # packet.ipv4.raw and packet.udp.raw reference the *exact* same buffer as packet.raw so they also get "released".
    #packet.ipv4.raw.release()
    #packet.udp.raw.release()

    min_packet = MinimalPacket(packet)

    print(min_packet)

    return min_packet


def generate_stats(connection_stats):
    """
Given a list containing connection statistics, generates a human-readable representation of those statistics.
 This function was originally the override for __str__ (so you could just call print(session_info)) but it appears a lot
 of my assumptions about programming design need to go out the window when writing multi-processing programs.
    """
    print("connection_stats: ", connection_stats)
    str_gen = []  # A partially generated string. Concatenating strings in python using '+' is sub-optimal; O(n^2)
    #get = self.connection_stats
    for con_stat in connection_stats:
        info = con_stat.get_info()
        # TODO: Would an implementation of list that returns itself (to allow recursive .append() calls)
        #  instead of None (which is why we have so many lines) be useful?
        str_gen.append("IP: ")
        str_gen.append(info['ip'])
        #str_gen.append(" | Packets Received: ")
        #str_gen.append(str(info['packet_count']))
        str_gen.append(" | Tag: ")
        str_gen.append(info['tag'])
        str_gen.append("\n")

    # Once this loop is complete, the *actual* string object can be built.
    return "".join(str_gen)


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
    connection_stats: Array of ConnectionStats, which contain the calculations and statistics of connections. (duh)
    """
    def __init__(self, proxy_dict, proxy_list, proxy_queue, initial_ips=None):
        if initial_ips is None:
            initial_ips = []

        self.known_ips = proxy_dict
        # self.connection_stats = [ConnectionStats(IPTag("1.1.1.1", "test"))]
        self.connection_stats = proxy_list

        for ip_tag in initial_ips:
            print("ip_tag: " + str(ip_tag))
            self.add_con_stat_from_ip_tag(ip_tag)
        # Connection stats and known IPs are now initialised.

        print(self.known_ips)
        print(self.connection_stats)

        i = 0
        while i < len(self.connection_stats):
            print("ATTEMPTING TO ACCESS connection_stats[" + str(i) + "]")
            con_stat = self.connection_stats[i]
            print("ACCESS SUCCESSFUL")
            print(con_stat)
            i += 1

        #print("ATTEMPTING FOR LOOP")
        #for con_stat in self.connection_stats:
            #print(con_stat)

        """
        This is a queue of packets pending processing. I wanted to make adding packets to SessionInfo objects as light
        as possible because packets will come from the filtering thread and if not designed properly, would "block" the
        entire filter for as long as it took for SessionInfo to process that packet. This could lead to in-game
        latency at best, and possibly a program crash at worst (because the filter cannot process packets quickly
        enough and lead to memory exhaustion).
        
        So, "adding" a packet actually only puts it in this queue, and a different process will do the depletion (and 
        of course, processing) of packets in this queue.
        """
        self.packet_queue = proxy_queue

        #self.processing_thread = Process(target=self.run, args=())
        #self.processing_thread.daemon = True    # Terminate this thread if the parent gets terminated.

    #def start(self):
        #self.processing_thread.start()

    #def stop(self):
        #self.processing_thread.terminate()

    """
    A packet was received by the filter and is now being shared with SessionInfo.
    
    packet: The packet (as received by PyDivert)
    allowed: Whether the packet was allowed (true) or dropped (false).
    """
    def add_packet(self, packet, allowed):
        """
        We cannot waste any time waiting for a spot in the queue. This function is called in the context of the
        filtering thread and so processing will happen later (and almost certainly on a different thread).
        """
        print(packet)
        self.packet_queue.put((packet, allowed), block=False)

    #def run(self):
        """
        Continually (and indefinitely) process the packet queue. Obviously this should be run in its' own thread.
        """
        #while True:
            #self.process_item()
            #os.system('cls')  # clear the console for new print
            #print(self)  # When new packet received, update display.
            # Might be a good idea to add some sort of sleep here?

    def process_item(self, block=True):
        """
        Depletes the queue of a single packet that has been added from the filtering thread.
        Note that by default, whatever thread calls this method *will be blocked* until there is an item in the queue.
        If you don't want your thread blocked, you will need to handle Empty exceptions because the queue *will* be
        empty at some points during processing.
        """
        (packet, allowed) = self.packet_queue.get(block)  # If there is a packet in the queue, get it (or wait for one)
        self.process_packet(packet, allowed)              # Actually process the packet.
        return  # If you want to process another packet, you'll need to call this function again.

    def process_packet(self, packet, allowed):
        # We're only going to monitor inbound packets.
        if packet.is_inbound:
            ip = packet.src_addr

            # If we're not aware of this destination, a new ConnectionStat (and conseq. IPTag) is required.
            if ip not in self.known_ips:
                # TODO: We might be able to use IP ranges to give IPs custom tags. (e.g. ROCKSTAR, UNKNOWN (USA), etc.)
                self.add_con_stat_from_ip_tag(IPTag(ip, "UNKNOWN"))  # Now that the ConnectionStat exists, we can get it

            con_stat = self.get_con_stat_from_ip(ip)
            con_stat.add_packet(packet)  # Pass the packet down to ConnectionStat where metrics will be calculated

    """
    Adds an IP (with tag) to connection stats.
    """
    def add_con_stat_from_ip_tag(self, ip_tag):
        this_ip = ip_tag.get_ip()

        if this_ip in self.known_ips:
            return    # If this IP has already been added, don't do it again.

        self.known_ips[this_ip] = len(self.connection_stats)    # Add this_ip to dictionary with value of index into
        self.connection_stats.append(ConnectionStats(ip_tag))   # bruh.

        print("idk: ", self.connection_stats)
        i = 0
        while i < len(self.connection_stats):
            print("trying to print ", i)
            print(self.connection_stats[i])
            i += 1

    """
    Returns the connection stat object associated with this IP.
    
    NOTE: Will throw KeyError there is no ConnectionStat for the given ip.
    """
    def get_con_stat_from_ip(self, ip):
        return self.connection_stats[self.known_ips[ip]]  # Use known_ips to get the index into connection_stats.

    """
    Returns the human-readable representation of the current session.
    """


class IPTag:

    """
    Container method for storing an IP with an arbitrary String attached.
    """
    def __init__(self, ip, tag=""):
        self.ip = ip
        self.tag = tag

    def get_ip(self):
        return self.ip

    def get_tag(self):
        return self.tag


class ConnectionStats:

    """
    Stores the actual relevant information for a connection.
    """
    def __init__(self, ip_tag):
        self.ip = ip_tag.get_ip()
        self.tag = ip_tag.get_tag()
        #self.packets = Manager().list()    # REALLY? THIS IS WHAT WAS BREAKING IT!!!???
        self.packets = []

    """
    Give a packet to this connection statistic so the relevant information can be stored.
    """
    def add_packet(self, packet):
        self.packets.append(packet)  # For now, I'm just going to add it to the array. Actual stats can be added later.

    """
    Returns an anonymous dictionary of information about this connection.
    """
    def get_info(self):
        return {'ip': self.ip, 'tag': self.tag}#, 'packet_count': len(self.packets)}
