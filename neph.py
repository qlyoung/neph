#!/usr/bin/env python3
#
# neph, the interactive protocol fuzzer
# -------------------------------------
# Copyright (c) 2018, Quentin Young
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

import pprint
import protos as ps
import fuzzers as fz
from protos import *
from fuzzers import *

# Imports for interactive mode-------------------------------------------------


# -----------------------------------------------------------------------------

version = "0.0.1"
pp = pprint.PrettyPrinter(indent=4)

helpmsg = """
Welcome to neph, the interactive protocol fuzzer.

Neph is a set of flexible building blocks you can use to build complex fuzzers
for all kinds of network protocols. It is a wrapper around Scapy that provides
two additional pieces of functionality:

- Implementations of protocols
- Enhanced fuzzing utilities

These pieces are designed to be mixed and matched.

For a complete reference, see the docs.
To see a list of protocols, use protocols().
To see a list of fuzzers, use fuzzers().
"""


def help():
    print(helpmsg)


def fuzzers():
    pp.pprint(fz.fuzzers)


def protocols():
    pp.pprint(ps.protocols)


if __name__ == "__main__":
    print("neph, the interactive protocol fuzzer")
    print("version {}".format(version))
