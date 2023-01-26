import timeit
from typing import Any

from network.iptag import IPTag
from network.minimalpacket import MinimalPacket


class ConnectionStats:
    """
    Stores the actual relevant information for a connection.
    """

    def __init__(self, ip_tag: IPTag):
        self.ip_tag = ip_tag
        self.packets: list[MinimalPacket] = []
        self.last_seen = 0.0
        self.packets_in = 0
        self.packets_out = 0
        self.packets_allowed = 0
        self.packets_dropped = 0
        self.session_requests = 0

    def add_packet(self, packet: MinimalPacket, allowed: bool) -> None:
        """
        Give a packet to this connection statistic so the relevant information can be stored.
        """
        self.packets.append(packet)
        if (
            packet.is_outbound
            and packet.payload_length == 125
            and not self.is_connected(3)
        ):
            self.session_requests += 1
        self.last_seen = timeit.default_timer()

        # Generic counters
        if packet.is_inbound:
            self.packets_in += 1
        elif packet.is_outbound:
            self.packets_out += 1

        if allowed:
            self.packets_allowed += 1
        else:
            self.packets_dropped += 1

    def is_connected(self, threshold: int = 5) -> bool:
        # If we haven't seen any activity from this source in the last 'threshold' seconds, then we're not connected.
        return (timeit.default_timer() - self.last_seen) <= threshold

    def get_last_seen_str(self):
        if self.last_seen == 0:
            return "Never"
        return f"{round((timeit.default_timer() - self.last_seen) * 1000)} ms ago"

    def get_tag_override(self):
        tag = self.ip_tag.tag

        # Local / Public IP tags take precedence.
        if tag in {"LOCAL IP", "PUBLIC IP"}:
            # TODO: Check if R* SERVICE
            return tag
        if self.is_connected():
            return "CONNECTED"
        elif self.session_requests > 0:
            return f"{self.session_requests}x JOIN REQ"
        return tag

    def get_info(self) -> dict[str, Any]:
        """
        Returns an anonymous dictionary of information about this connection.
        """
        return {
            "ip": self.ip_tag.ip,
            "tag": self.get_tag_override(),
            "packet_count": len(self.packets),
            "is_connected": self.is_connected(3),
            "last_seen": self.get_last_seen_str(),
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "packets_allowed": self.packets_allowed,
            "packets_dropped": self.packets_dropped,
        }
