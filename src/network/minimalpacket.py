from pydivert import Packet


class MinimalPacket:
    def __init__(self, packet: Packet):
        self.payload_length = len(packet.payload)
        self.src_addr = packet.src_addr
        self.src_port = packet.src_port
        self.dst_addr = packet.dst_addr
        self.dst_port = packet.dst_port
        self.is_inbound = packet.is_inbound
        self.is_outbound = packet.is_outbound
        self.direction = packet.direction
