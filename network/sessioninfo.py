

class SessionInfo:

    """
    Returns human-readable strings that expose session information to the user after being supplied captured packets.

    initial_ips: Array of IPTag that should be known before any traffic is received from them.

    known_ips: Dictionary of known IPs, used to check if an IP has been seen previously.
        Value stored is the index into an array of ConnectionStats.
    """
    def __init__(self, initial_ips = []):
        self.known_ips = {}
        self.connection_stats = []
        for ip_tag in initial_ips:
            this_ip = ip_tag.get_ip()
            self.known_ips[this_ip] = len(self.connection_stats)    # Add this_ip to dictionary with value of index into
            self.connection_stats.append(ConnectionStats(this_ip))  # self.connection_stats.



class IPTag:

    """
    Container method for storing an IP with an arbitrary String attached.
    """
    def __init__(self, ip, tag = ""):
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
        self.packets = []
