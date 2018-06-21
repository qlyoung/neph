# BGP fuzzing stuff.
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

from fuzzers.fuzz import FuzzerMixin
from protos.bgp import BGP


class BGPFuzzer(BGP, FuzzerMixin):
    """
    BGP protocol fuzzer.
    """

    def __init__(self, neighbor=None, my_as=0, bgp_id=None, fuzzspec=None):
        # initialize the protocol
        super().__init__(neighbor=neighbor, my_as=my_as, bgp_id=bgp_id)
        self.fuzzspec = fuzzspec or {
            "BGPOpen": {
                "header": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "version": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "my_as": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "hold_time": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "bgp_id": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "opt_param_len": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "opt_params": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
            },
            "BGPKeepalive": {
                "header": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                }
            },
            "BGPUpdate": {
                "withdrawn_routes_len": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "withdrawn_routes": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "path_attr_len": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "path_attr": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "nlri": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
            },
            "BGPNotification": {
                "error_code": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "error_subcode": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
                "data": {
                    "fuzz": False,
                    "value": "default",
                    "strategies": ["bitflip", "increment"],
                },
            },
        }

    def make_pkt(self, pktcls, *args, **kwargs):
        msg = super().make_pkt(pktcls, *args, **kwargs)
        # perform fuzzing routines
        return msg
