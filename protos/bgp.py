from socket import socket
from nephcli import NephCLI
from prompt_toolkit import prompt
from scapy.config import conf
from scapy.all import *
from scapy.contrib.bgp import *
from scapy.automaton import *

class BGPAutomaton(Automaton):
    """
    BGP FSM implemented as a Scapy automaton.

    .. note::
       The Automaton class provides a built in socket that by default is used
       to drive the automaton. Due to the way it is implemented this socket
       must be a PF_PACKET type socket, i.e. in order to use it we'd have to
       drive TCP/IP ourselves. Since BGP uses TCP as its transport, this is a
       pain in the ass. Instead we ignore that functionality and drive our own
       TCP socket using the kernel's TCP stack.

    .. caveats::
       - Only active mode is supported
       - Only IPv4 is supported

    .. seealso:: :rfc;`4271`
    """

    # some sane defaults
    defaults = {
        "ConnectRetryTime": 1,
        "HoldTime": 90,
        "KeepaliveTime": 30,
    }

    def parse_args(self, neighbor, my_as, bgp_id, timers=None, **kargs):
        """
        Sets up the BGP automaton.

        :param neighbor: ipv4 address of bgp peer
        :param my_as: local autonomous system number
        :param bgp_id: bgp identifier
        :param timers: session timers; keys should be named with the exact name
        used in :rfc:`4271`. For example, to specify the hold time, set
        timers['HoldTime'] equal to the value in seconds.
        :param kargs: additional args, passed through to Automaton.parse_args

        :type neighbor: str
        :type my_as: int
        :type bgp_id: str
        :type timers: dict
        """
        Automaton.parse_args(self, **kargs)

        self.sattrs = {
            'ConnectRetryCounter': 0,
            'ConnectRetryTime': self.defaults['ConnectRetryTime'],
            'HoldTime': self.defaults['HoldTime'],
            'KeepaliveTime': self.defaults['KeepaliveTime'],
        }

        if timers is not None:
            self.sattrs['HoldTime'] = timers['HoldTime']
            self.sattrs['KeepaliveTime'] = timers['KeepaliveTime']

        self.firstrun = True
        self.neighbor = neighbor
        self.my_as = my_as
        self.bgp_id = bgp_id
        # neighbor socket and supersocket
        self.ns = None
        self.nss = None

    def _log_state_change(self, orig, new):
        print("[~] {} -> {}".format(orig, new))

    def _cleanup_sockets(self):
        """Closes and None's all sockets"""
        if self.ns is not None:
            self.ns.close()
        if self.nss is not None:
            self.nss.close()
        self.ns = None
        self.nss = None

    def _send_keepalive(self):
        """Sends a KEEPALIVE to peer"""
        print("[+] Sending KEEPALIVE")
        bgpka = BGPKeepAlive()
        self.nss.send(bgpka)

    @ATMT.state(initial=True)
    def IDLE(self):
        self.ns = socket.socket()
        if not self.firstrun:
            print("[+] Connecting in {}s".format(crt))
            time.sleep(self.sattrs['ConnectRetryTime'])
        self._log_state_change(self.IDLE.__name__, self.CONNECT.__name__)
        raise self.CONNECT()

    @ATMT.state()
    def CONNECT(self):
        """
        In this state, BGP FSM is waiting for the TCP connection to be
        completed.

        As a simplification, the TCP connection is not started in IDLE and
        instead is started and completed here. Additionally, instead of using
        dedicated timers, the socket operation timeout value is used as a fake
        timer.
        """
        crt = self.sattrs['ConnectRetryTime']
        self.ns.settimeout(crt)
        try:
            self.ns.connect((self.neighbor, 179))
        except Exception as ex:
            print("[!] TCP connection failed: {}".format(ex))
            self._cleanup_sockets()
            self._log_state_change(self.CONNECT.__name__, self.IDLE.__name__)
            raise self.IDLE()

        # at this point we can wrap the socket in a StreamSocket
        self.nss = StreamSocket(self.ns)

        # If the TCP connection succeeds...the local system:
        # - sends an OPEN message to its peer
        ht = self.sattrs['HoldTime']
        bgpopen = BGPHeader()/BGPOpen(my_as=self.my_as, hold_time=ht, bgp_id=self.bgp_id)

        print("[+] Sending OPEN:")
        bgpopen.show()

        try:
            self.nss.send(bgpopen)
        except:
            print("[!] OPEN send failed".format(st))
            self._cleanup_sockets()
            self._log_state_change(self.CONNECT.__name__, self.IDLE.__name__)
            raise self.IDLE()

        print("[+] Sent OPEN")

        # - sets the HoldTimer to a large value
        self.ns.settimeout(self.sattrs['HoldTime'])
        # - and changes its state to OpenSent.
        self._log_state_change(self.CONNECT.__name__, self.OPENSENT.__name__)
        raise self.OPENSENT()

    @ATMT.state()
    def OPENSENT(self):
        """
        In this state, BGP FSM waits for an OPEN message from its peer.
        """
        print("[+] Waiting to receive OPEN...")
        try:
            recvbuf = self.nss.recv(BGP_MAXIMUM_MESSAGE_SIZE)
        except Exception as ex:
            print("[!] Exception in OPENSENT: {}".format(ex))
            # If the HoldTimer_Expires (Event 10), the local system:
            # - sends a NOTIFICATION message with the error code Hold Timer
            #   Expired
            # FIXME: check if exception type is timeout
            print("[!] Sending NOTIFICATION")
            bgpnotify = BGPNotification(error_code=0x04)
            self.nss.send(bgpnotify)
            # - sets the ConnectRetryTimer to zero,
            # - releases all BGP resources,
            # - drops the TCP connection,
            self._cleanup_sockets()
            # - increments the ConnectRetryCounter,
            self.sattrs['ConnectRetryCounter'] += 1
            # - changes its state to Idle.
            self._log_state_change(self.OPENSENT.__name__, self.IDLE.__name__)
            raise self.IDLE()

        try:
            rcvdopen = BGPOpen(recvbuf)
        except Exception as ex:
            print("[!] Failed to parse message as OPEN: {}".format(ex))
            self._cleanup_sockets()
            self._log_state_change(self.OPENSENT.__name__, self.IDLE.__name__)
            raise self.IDLE()

        print("[+] Received OPEN")
        rcvdopen.show()

        # When an OPEN message is received, all fields are checked for
        # correctness. If there are no errors in the OPEN message (Event 19),
        # the local system:
        # - sends a KEEPALIVE message
        self._send_keepalive()
        # - sets a KeepaliveTimer
        # - sets the HoldTimer according to the negotiated value
        # - changes its state to OpenConfirm.
        self._log_state_change(self.OPENSENT.__name__, self.OPENCONFIRM.__name__)
        raise self.OPENCONFIRM()

    @ATMT.state()
    def OPENCONFIRM(self):
        """
        In this state, BGP waits for a KEEPALIVE or NOTIFICATION message.
        """
        try:
            recvbuf = self.nss.recv(BGP_MAXIMUM_MESSAGE_SIZE)
        except:
            self._cleanup_sockets()
            self._log_state_change(self.OPENCONFIRM.__name__, self.IDLE.__name__)
            raise self.IDLE()

        try:
            rcvdopen = BGPKeepAlive(recvbuf)
        except Exception as ex:
            print("[!] Failed to parse message as KEEPALIVE: {}".format(ex))
            self._cleanup_sockets()
            self._log_state_change(self.OPENCONFIRM.__name__, self.IDLE.__name__)
            raise self.IDLE()

        print("[+] Received KEEPALIVE")

        # If the local system receives a KEEPALIVE message, the local system:
        # - restarts the HoldTimer and
        # - changes its state to Established.
        self._log_state_change(self.OPENCONFIRM.__name__, self.ESTABLISHED.__name__)
        raise self.ESTABLISHED()

    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.timeout(ESTABLISHED, 5)
    def established_ka_timer(self):
        self._send_keepalive()
        raise self.ESTABLISHED()


# CLI shit ---------------------------------------------------------------------

class BgpCLI(NephCLI):
    def __init__(self):
        super().__init__()
        self.prompt = "(bgp)>>"

def cmd_bgp(cmd):
    print(BGPAutomaton.graph())
    n = prompt("neighbor: ")
    my_as = prompt("local as: ")
    bgp_id = prompt("bgp_id: ")

    b = BGPAutomaton(neighbor=n, my_as=int(my_as), bgp_id=bgp_id)
    b.run()

def repl():
    cli = BgpCLI()
    cli.add_cmd("fuzzopen", cmd_bgp)
    cli.repl()
