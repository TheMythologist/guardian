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


def safe_pickle_packet(packet: Packet) -> MinimalPacket:
    """
    Returns a variant of a PyDivert packet that:
    a) can be pickled (typical PyDivert packets use MemoryView which cannot be pickled)
    b) has had certain untrusted, external information redacted (code execution can occur when unpickling, i.e.
       certain externally-controllable characteristics like packet content should be removed)
    """
    # Delete the raw payload content. We don't need it (it's encrypted anyways) and modded clients can send raw bytes
    # to other clients, including us, which could allow arbitrary code execution to occur when unpickling packet objects.
    # (See https://docs.python.org/3/library/pickle.html)

    # TODO: Investigate performance of serialization with JSON instead of pickling to improve program security.
    return MinimalPacket(packet)
