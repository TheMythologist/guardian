from multiprocessing import Manager, Process
import os


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
            ip = packet.ip.src_addr

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

    """
    Give a packet to this connection statistic so the relevant information can be stored.
    """
    #def add_packet(self, packet):
        #self.packets.append(packet)  # For now, I'm just going to add it to the array. Actual stats can be added later.

    """
    Returns an anonymous dictionary of information about this connection.
    """
    def get_info(self):
        return {'ip': self.ip, 'tag': self.tag}#, 'packet_count': len(self.packets)}
