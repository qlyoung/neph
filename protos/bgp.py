from nephcli import NephCLI
from prompt_toolkit import prompt

import scapy
from scapy.all import *
from scapy.contrib.bgp import *
from scapy.automaton import *

class BGPAutomaton(Automaton):
    """
    BGP FSM implemented as a Scapy automaton.
    Only active mode is supported.
    """

    # some sane defaults
    defaults = {
        "ConnectRetryTimer": 1,
        "HoldTime": 90,
        "KeepaliveTime": 30,
        "HoldTimer": 60 * 4,
    }

    # session attributes
    sattrs = {
      "State": None,
      "ConnectRetryCounter": 0,
      "ConnectRetryTimer": 0,
      "ConnectRetryTime": 0,
      "HoldTimer": None,
      "HoldTime": 0,
      "KeepaliveTimer": None,
      "KeepaliveTime": None,
    }

    # timers = (keepalive, hold)
    # asn = (local, remote)
    # neighbor = v4 addr
    def parse_args(self, neighbor, my_as, bgp_id, timers=None, **kargs):
        Automaton.parse_args(self, **kargs)
        self.neighbor = neighbor
        if timers is not None:
            self.defaults["HoldTime"] = timers[0]
            self.defaults["KeepaliveTime"] = timers[1]
        self.my_as = my_as
        self.bgp_id = bgp_id

    @ATMT.state(initial=True)
    def IDLE(self):
        print("[+] State=IDLE")
        self.sattrs["ConnectRetryCounter"] = 0
        self.sattrs["ConnectRetryTimer"] = self.defaults["ConnectRetryTimer"]
        # Pretend we initiated a TCP connection to peer
        raise self.CONNECT()

    @ATMT.state()
    def CONNECT(self):
        print("[+] State=CONNECT")
        # the local system:
        # - sets the ConnectRetryTimer to 0
        self.sattrs["ConnectRetryTimer"] = 0
        # - Completes BGP initialization
        # - Sends OPEN message to peer
        ht = self.sattrs["HoldTime"]
        bgpopen = IP(dst=self.neighbor)/TCP(dport=179)/BGPOpen(my_as=self.my_as, hold_time=ht, bgp_id=self.bgp_id)
        #try:
        self.send(bgpopen)
        #except:
        #    # if the TCP connection fails...the local system:
        #    # - stops the ConnectRetryTimer to zero,
        #    self.sattrs["ConnectRetryTimer"] = 0
        #    # - drops the TCP connection,
        #    # - releases all BGP resources, and
        #    # - changes its state to Idle.
        #    raise self.IDLE()

        print("[+] Sent OPEN")
        # - Sets the HoldTimer to a large value
        self.sattrs["HoldTimer"] = self.defaults["HoldTimer"]
        # - changes its state to OpenSent
        raise self.OPENSENT()

    @ATMT.state()
    def OPENSENT(self):
        print("[+] State=OPENSENT")
        pass

    @ATMT.receive_condition(OPENSENT)
    def receive_opensent(self, pkt):
        # send keepalive
        bgpka = IP(dst=self.neighbor)/TCP(dport=179)/BGPKeepAlive()
        self.send(bgpka)

# CLI shit ---------------------------------------------------------------------

class BgpCLI(NephCLI):
    def __init__(self):
        super().__init__()
        self.prompt = "(bgp)>>"

def cmd_bgp(cmd):
    neighbor = prompt("neighbor: ")
    my_as = prompt("local as: ")
    bgp_id = prompt("bgp_id: ")

    b = BGPAutomaton(neighbor, int(my_as), bgp_id)
    b.run()

def repl():
    cli = BgpCLI()
    cli.add_cmd("fuzzopen", cmd_bgp)
    cli.repl()
