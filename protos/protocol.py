# Package control for neph protocols.
# -----------------------------------
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


class NephProtocol(object):
    """
    Abstract base class for neph protocol implementations.

    Subclasses should override everything defined here.
    """

    # List of Scapy packet classes used in the protocol
    packets = []

    # Human readable name
    name = ""

    def make_pkt(self, pktcls, *args, **kwargs):
        """
        Make a packet of the specified class.

        This serves as an interception point for fuzzers.
        """
        pass

    # Run the protocol
    def run(self):
        pass
