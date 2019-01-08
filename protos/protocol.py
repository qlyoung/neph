# Common functionality for Neph protocol implementations.
# -------------------------------------------------------
# Copyright (c) 2018, Quentin Young.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from twisted.internet import task
import logging


class NephProtocol(object):
    """
    Abstract base class for neph protocol implementations.

    Subclasses should override everything defined here.
    """

    packets = []
    """List of Scapy packet classes used in the protocol"""

    name = ""
    """Human readable name"""

    def make_pkt(self, pktcls, *args, **kwargs):
        """
        Make a packet of the specified class.

        This serves as a hook point for fuzzers.
        """
        pass

    def run(self):
        """Run the protocol."""
        pass


class NephTimer(object):
    """Timer implementation based on Twisted."""

    def errback(failure):
        """Print error traceback."""
        print(failure.getBriefTraceback())

    def __init__(self, time, name=None, handler=None, logger=None):
        """
        Create a new NephTimer.

        .. param name:: name of this timer
        .. param time:: value of timer
        .. param handler::
        """
        self.name = name or "unnamed"
        self.time = int(time)
        self.handler = handler
        self.timer = task.LoopingCall(self.handler)
        self.log = logging.getLogger(logger)

    def start(self):
        if self.time <= 0:
            raise ValueException("Timer value must be positive")

        self.log.info("[+] Starting timer {}".format(self.name))
        self.timer.start(self.time, now=False).addErrback(self.errback)

    def stop(self):
        self.log.info("[+] Stopping timer {}".format(self.name))
        if self.timer.running:
            self.timer.stop()
        else:
            self.log.info("[+] Timer {} already stopped".format(self.name))

    def restart(self):
        self.log.info(
            "[+] Restarting {} timer {} ({}s)".format(
                self.name, "running" if self.timer.running else "stopped", self.time
            )
        )
        if self.timer.running:
            self.timer.reset()
        else:
            self.start()
