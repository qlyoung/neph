#!/usr/bin/env python3
#
# neph, the interactive protocol fuzzer
# -------------------------------------
# Driver

import pprint
import protos as ps
import fuzzers as fz
from protos import *
from fuzzers import *

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
    

if __name__ == '__main__':
    print("neph, the interactive protocol fuzzer")
    print("version {}".format(version))
