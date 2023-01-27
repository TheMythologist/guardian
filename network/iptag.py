class IPTag:
    """
    Container method for storing an IP with an arbitrary String attached.
    """

    def __init__(self, ip: str, tag: str = ""):
        self.ip = ip
        self.tag = tag

    def set_tag(self, tag: str) -> None:
        self.tag = tag
