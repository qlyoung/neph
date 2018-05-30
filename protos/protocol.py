import scapy.packet

class NephProtocol(object):
    """
    Abstract base class for neph protocol implementations.

    Subclasses should override everything defined here.
    """
    packets = []
    name = ""

    def make_pkt(self, pkt):
        pass

    def run(self):
        pass
