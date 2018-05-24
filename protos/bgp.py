from io import BytesIO
from socket import socket
from nephcli import NephCLI
from prompt_toolkit import prompt
from scapy.config import conf
from scapy.all import *
from scapy.contrib.bgp import *
from scapy.automaton import *
from transitions import Machine
from twisted.internet import reactor
from twisted.internet import task
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from functools import partial
import logging

class BGP(Protocol):
    """
    BGP protocol implementation.

    All state and event names are exactly those used in :rfc:`4271`.
    Only `Mandatory` events are supported. No cream, no sugar.

    .. seealso:: :rfc:`4271`
    """

    # Internal classes ---------------------------------------------------------

    class BGPTimer(object):

        def errback(failure):
            print(failure.getBriefTraceback())

        def __init__(self, name=None, time=0, handler=None):
            self.name = name or "unnamed"
            self.time = time
            self.timer = None
            self.handler = handler
            self.args = None
            self.log = logging.getLogger('BGP')
            self.log.setLevel(level=logging.INFO)

        def start(self, *args):
            if self.time == 0:
                raise ValueException("Timer value must be positive")

            self.log.info("[+] Starting timer {}".format(self.name))
            self.timer = task.LoopingCall(self.handler, *args)
            self.timer.start(self.time, now=False).addErrback(self.errback)
            self.args = args

        def stop(self):
            if not self.timer:
                self.log.info("[!] Stopping nonexistent timer")
                return

            self.log.info("[+] Stopping timer {}".format(self.name))
            if self.timer.running:
                self.timer.stop()
            else:
                self.log.info("[+] timer {} already stopped".format(self.name))

        def restart(self):
            if not self.timer:
                self.log.info("[!] Restarting nonexistent timer")
                self.start()
                return

            self.log.info("[+] Restarting timer {}".format(self.name))
            if self.timer.running:
                self.timer.reset()
            else:
                self.log.info("[+] Timer {} was not running".format(self.name))
                self.timer.start(self.time)


    # Class attributes ---------------------------------------------------------

    # Default session attributes
    defaults = {
        "ConnectRetryTime": 5,
        "HoldTime": 90,
        "KeepaliveTime": 30,
    }

    # Various BGP constants
    MAXIMUM_MESSAGE_SIZE = 4096
    HEADER_SIZE = 19
    MARKER_SIZE = 16
    MARKER = b'\xff' * 16
    MESSAGE_TYPES = {
        0: "NONE",
        1: "OPEN",
        2: "UPDATE",
        3: "NOTIFICATION",
        4: "KEEPALIVE",
        5: "ROUTE-REFRESH"
    }

    # FSM states
    states = ['Idle', 'Connect', 'Active', 'OpenSent', 'OpenConfirm', 'Established']

    # Public methods -----------------------------------------------------------

    def __init__(self, neighbor, my_as, bgp_id, attrs=None):
        """
        Create a new BGP.

        :param neighbor: ipv4 address of bgp peer
        :param my_as: local autonomous system number
        :param bgp_id: bgp identifier
        :param attrs: session attributes, see :rfc:`4271`

        :type neighbor: str
        :type my_as: int
        :type bgp_id: str
        :type timers: dict
        """
        self.fsm = Machine(model=self, states=BGP.states, initial='Idle')
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('transitions').setLevel(level=logging.INFO)

        self.log = logging.getLogger('BGP')
        self.log.setLevel(level=logging.INFO)

        self.events = {
            # 8.1.2.  Administrative Events
            'ManualStart': self.on_ManualStart,
            'ManualStop': self.on_ManualStop,
            # 8.1.3.  Timer Events
            'ConnectRetryTimer_Expires': self.on_ConnectRetryTimer_Expires,
            'HoldTimer_Expires': self.on_HoldTimer_Expires,
            'KeepaliveTimer_Expires': self.on_KeepaliveTimer_Expires,
            # 8.1.4.  TCP Connection-Based Events
            'Tcp_CR_Acked': self.on_Tcp_CR_Acked,
            'TcpConnectionConfirmed': self.on_TcpConnectionConfirmed,
            'TcpConnectionFails': self.on_TcpConnectionFails,
            # 8.1.5.  BGP Message-Based Events
            'BGPOpen': self.on_BGPOpen,
            'BGPHeaderErr': self.on_BGPHeaderErr,
            'BGPOpenMsgErr': self.on_BGPOpenMsgErr,
            'NotifMsgVerErr': self.on_NotifMsgVerErr,
            'NotifMsg': self.on_NotifMsg,
            'KeepAliveMsg': self.on_KeepAliveMsg,
            'UpdateMsg': self.on_UpdateMsg,
            'UpdateMsgErr': self.on_UpdateMsgErr,
        }

        self.msgbuilders = {
            'OPEN': self.make_OPEN,
            'KEEPALIVE': self.make_KEEPALIVE,
            'UPDATE': self.make_UPDATE,
            'NOTIFICATION': self.make_NOTIFICATION,
        }

        self.sattrs = {
            'ConnectRetryCounter': 0,
        }

        kat = self.defaults['KeepaliveTime']
        hlt = self.defaults['HoldTime']
        crt = self.defaults['ConnectRetryTime']
        katex = partial(self._event, 'KeepaliveTimer_Expires')
        crtex = partial(self._event, 'ConnectRetryTimer_Expires')
        hltex = partial(self._event, 'HoldTimer_Expires')

        self.sattrs['timers'] = {
            'KeepaliveTimer': BGP.BGPTimer("KeepaliveTimer", kat, katex),
            'ConnectRetryTimer': BGP.BGPTimer("ConnectRetryTimer", crt, crtex),
            'HoldTimer': BGP.BGPTimer("HoldTimer", hlt, hltex)
        }

        self.neighbor = neighbor
        self.my_as = int(my_as)
        self.bgp_id = bgp_id

        # Twisted Shit
        self.point = TCP4ClientEndpoint(reactor, neighbor, 179)
        self.inbuf = BytesIO()

    def run(self):
        self._event('ManualStart')
        reactor.run()
        self._event('ManualStop')

    # FSM event handlers -------------------------------------------------------

    def _event(self, event, *args):
        self.log.info("[+] Event '{}' in state '{}'".format(event, self.state))
        self.events[event](*args)

    def on_ManualStart(self):
        if self.state == 'Idle':
            # In response to a ManualStart event (Event 1) or an AutomaticStart
            # event (Event 3), the local system:
            #
            # - initializes all BGP resources for the peer connection,
            # - sets ConnectRetryCounter to zero,
            self.sattrs['ConnectRetryCounter'] = 0
            # - starts the ConnectRetryTimer with the initial value,
            # self.sattrs['timers']['ConnectRetryTimer'].start()
            # - initiates a TCP connection to the other BGP peer,
            connectProtocol(self.point, self)
            # - listens for a connection that may be initiated by the remote
            #   BGP peer, and
            # FIXME
            # - changes its state to Connect.
            self.to_Connect()

    def on_ManualStop(self):
        if self.state == 'Connect':
            # In response to a ManualStop event (Event 2), the local system:
            # - drops the TCP connection,
            if self.transport:
                self.transport.loseConnection()
            # - releases all BGP resources,
            # - sets ConnectRetryCounter to zero,
            self.sattrs['ConnectRetryCounter'] = 0
            # - stops the ConnectRetryTimer and sets ConnectRetryTimer to zero,
            self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - changes its state to Idle.
            self.to_Idle()
        elif self.state in ['OpenSent', 'OpenConfirm']:
            # If a ManualStop event (Event 2) is issued in the OpenSent state,
            # the local system:
            # - sends the NOTIFICATION with a Cease,
            self.send_bgp_msg('NOTIFICATION', error_code=0x06)
            # - sets the ConnectRetryTimer to zero,
            self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - releases all BGP resources,
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - sets the ConnectRetryCounter to zero, and
            self.sattrs['ConnectRetryCounter'] = 0
            # - changes its state to Idle.
            self.to_Idle()
        elif self.state == 'Established':
            # In response to a ManualStop event (initiated by an operator)
            # (Event 2), the local system:
            # - sends the NOTIFICATION message with a Cease,
            self.send_bgp_msg('NOTIFICATION', error_code=0x06)
            # - sets the ConnectRetryTimer to zero,
            self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - deletes all routes associated with this connection,
            # - releases BGP resources,
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - sets the ConnectRetryCounter to zero, and
            self.sattrs['ConnectRetryCounter'] = 0
            # - changes its state to Idle.
            self.to_Idle()

    def on_ConnectRetryTimer_Expires(self):
        if self.state == 'Idle':
            self.sattrs['timers']['ConnectRetryTimer'].stop()
            self._event('ManualStart')

    def on_HoldTimer_Expires(self):
        if self.state in ['OpenSent', 'OpenConfirm', 'Established']:
            # If the HoldTimer_Expires (Event 10), the local system:
            # - sends a NOTIFICATION message with the error code Hold Timer
            #   Expired,
            self.send_bgp_msg('NOTIFICATION', error_code=0x04)
            # - sets the ConnectRetryTimer to zero,
            # self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - releases all BGP resources,
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - increments the ConnectRetryCounter,
            self.sattrs['ConnectRetryCounter'] += 1
            # - changes its state to Idle.
            self.to_Idle()

    def on_KeepaliveTimer_Expires(self):
        if self.state == 'Established':
            # If the KeepaliveTimer_Expires event occurs (Event 11), the local
            # system:
            # - sends a KEEPALIVE message
            self.send_bgp_msg('KEEPALIVE')
            # - restarts its KeepaliveTimer, unless the negotiated HoldTime
            #   value is zero.
            # FIXME
            self.sattrs['timers']['KeepaliveTimer'].restart()

    def on_TcpConnectionFails(self):
        self.sattrs['timers']['KeepaliveTimer'].stop()
        self.sattrs['timers']['HoldTimer'].stop()
        if self.state in ['Connect', 'OpenSent', 'OpenConfirm']:
            # If the DelayOpenTimer is not running, the local system:
            # - stops the ConnectRetryTimer to zero,
            #self.sattrs['timers']['ConnectRetryTimer'].restart()
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - releases all BGP resources, and
            # - changes its state to Idle.

        self.to_Idle()
        self.sattrs['timers']['ConnectRetryTimer'].restart()

    def on_TcpConnectionConfirmed(self):
        if self.state == 'Connect':
            # the local system:
            # - stops the ConnectRetryTimer (if running) and sets the
            #   ConnectRetryTimer to zero,
            # self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - completes BGP initialization
            # - sends an OPEN message to its peer,
            self.send_bgp_msg('OPEN')
            # - sets the HoldTimer to a large value, and
            ht = self.sattrs['timers']['HoldTimer'].start()
            # - changes its state to OpenSent.
            self.to_OpenSent()
        elif self.state == 'OpenSent':
            # connection collision resolution
            pass

    def on_Tcp_CR_Acked(self):
        self.on_TcpConnectionConfirmed()

    def on_BGPOpen(self, data):
        if self.state == 'OpenSent':
            # When an OPEN message is received, all fields are checked for
            # correctness.
            # FIXME
            #If there are no errors in the OPEN message (Event
            # 19), the local system:
            # - sets the BGP ConnectRetryTimer to zero,
            # self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - sends a KEEPALIVE message, and
            self.send_bgp_msg('KEEPALIVE')
            # - sets a KeepaliveTimer (via the text below)
            self.sattrs['timers']['KeepaliveTimer'].start()
            # - sets the HoldTimer according to the negotiated value (see
            #   Section 4.2),
            # FIXME: negotiate value
            ht = self.sattrs['timers']['HoldTimer'].restart()
            # - changes its state to OpenConfirm.
            self.to_OpenConfirm()

    def on_BGPHeaderErr(self, data):
        pass

    def on_BGPOpenMsgErr(self, data):
        pass

    def on_NotifMsgVerErr(self, data):
        pass

    def on_NotifMsg(self, data):
        if self.state == 'Established':
            # If the local system receives a NOTIFICATION message (Event 24 or
            # Event 25) or a TcpConnectionFails (Event 18) from the underlying
            # TCP, the local system:
            # - sets the ConnectRetryTimer to zero,
            # self.sattrs['timers']['ConnectRetryTimer'].stop()
            # - deletes all routes associated with this connection,
            # - releases all the BGP resources,
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - increments the ConnectRetryCounter by 1,
            self.sattrs['ConnectRetryCounter'] += 1
            # - changes its state to Idle.
            self.to_Idle()
        if self.state == 'OpenSent':
            # In response to any other event (Events 9, 11-13, 20, 25-28), the
            # local system:
            # - sends the NOTIFICATION with the Error Code Finite State
            #   Machine Error,
            self.send_bgp_msg('NOTIFICATION', error_code=0x05)
            # - sets the ConnectRetryTimer to zero,
            # self.sattrs['timers']['ConnectRetryTimer'].start()
            # - releases all BGP resources,
            # - drops the TCP connection,
            self.transport.loseConnection()
            # - increments the ConnectRetryCounter by 1,
            self.sattrs['ConnectRetryCounter'] += 1

    def on_KeepAliveMsg(self, data):
        if self.state == 'OpenConfirm':
            # If the local system receives a KEEPALIVE message (KeepAliveMsg
            # (Event 26)), the local system:
            # - restarts the HoldTimer
            self.sattrs['timers']['HoldTimer'].restart()
            # - changes its state to Established.
            self.to_Established()
        if self.state == 'Established':
            # If the local system receives a KEEPALIVE message (Event 26), the
            # local system:
            # - restarts its HoldTimer, if the negotiated HoldTime value is
            #   non-zero
            self.sattrs['timers']['HoldTimer'].restart()
            # - remains in the Established state.

    def on_UpdateMsg(self, data):
        if self.state == 'Established':
            # If the local system receives an UPDATE message (Event 27), the
            # local system:
            # - processes the message,
            # FIXME
            # - restarts its HoldTimer, if the negotiated HoldTime value is
            #   non-zero
            self.sattrs['timers']['HoldTimer'].reset()
            # - remains in the Established state.

    def on_UpdateMsgErr(self, data):
        pass

    # Message handling ---------------------------------------------------------

    def make_OPEN(self):
        ht = self.sattrs['timers']['HoldTimer'].time
        bgpopen = BGPHeader()/BGPOpen(hold_time=ht, bgp_id=self.bgp_id, my_as=self.my_as)
        return bgpopen

    def make_NOTIFICATION(self, error_code=0x04):
        return BGPHeader()/BGPNotification(error_code=error_code)

    def make_KEEPALIVE(self):
        return BGPKeepAlive()

    def make_UPDATE(self):
        pass

    def recv_bgp_msg(self, msgtype, msglen, msg):
        if msgtype not in BGP.MESSAGE_TYPES:
            msgtype = 0
        msgtypestr = BGP.MESSAGE_TYPES[msgtype]

        self.log.info("[<] {}".format(msgtypestr))
        self.log.info("    | len: {}".format(msglen))
        self.log.info("    | type: {} ({})".format(msgtypestr, msgtype))

        if msgtypestr == 'OPEN':
            self._event('BGPOpen', packet)
        elif msgtypestr == 'UPDATE':
            self._event('Update', packet)
        elif msgtypestr == 'NOTIFICATION':
            self._event('NotifMsg', packet)
        elif msgtypestr == 'KEEPALIVE':
            self._event('KeepAliveMsg', packet)
        elif msgtypestr == 'ROUTE-REFRESH':
            pass

    def send_bgp_msg(self, type, *args, **kwargs):
        self.log.info("[>] {}".format(type))
        msg = self.msgbuilders[type](*args, **kwargs)
        self.transport.write(bytes(msg))

    def handle_data_received(self):
        """
        Parse incoming data, segment into BGP messages, and invoke the
        appropriate message handler.
        """
        if self.inbuf.tell() < BGP.HEADER_SIZE:
            return

        v = self.inbuf.getbuffer()
        header = v[0:BGP.HEADER_SIZE]

        msglen = int.from_bytes(v[16:18], byteorder='big')
        msgtype = int(v[18])

        # check marker
        if header[0:16] != BGP.MARKER:
            self._event('BGPHeaderErr', header)
            return

        # validate length field
        if msglen < BGP.HEADER_SIZE or msglen > BGP.MAXIMUM_MESSAGE_SIZE:
            self._event('BGPHeaderErr', header)
            return

        # validate type field
        if msgtype == 0 or msgtype not in BGP.MESSAGE_TYPES:
            self._event('BGPHeaderErr', header)

        # check that we have the amount of data specified in the length field
        if self.inbuf.tell() < msglen:
            return

        # if all these conditions check out, we have a full message
        packet = self.inbuf.read(msglen)
        self.inbuf = BytesIO(v[msglen:])
        self.inbuf.seek(0, 2)
        self.recv_bgp_msg(msgtype, msglen, packet)

    # Twisted ------------------------------------------------------------------

    def dataReceived(self, data):
        self.log.info("[=] Twisted: Data received")
        self.inbuf.write(data)
        self.handle_data_received()

    def connectionLost(self, reason):
        self.log.info("[=] Twisted: Connection lost")
        self._event('TcpConnectionFails')

    def connectionMade(self):
        self.log.info("[=] Twisted: Connection made")
        self._event('TcpConnectionConfirmed')

