#!/usr/bin/env python3
#
# neph, the interactive protocol fuzzer
# -------------------------------------
# Driver

import pkgutil
import protos
from nephcli import NephCLI
from fuzzers import *

version = "0.0.1"

def cmd_modules(cmd):
    for module in pkgutil.iter_modules(['fuzzers']):
        print(module.name)

def cmd_enter_module(cmd):
    bgpfuzzer.repl()
    

if __name__ == '__main__':
    print("neph, the interactive protocol fuzzer")
    print("version {}".format(version))

    cli = NephCLI()
    cli.add_cmd("modules", cmd_modules)
    for module in pkgutil.iter_modules(['fuzzers']):
        cli.add_cmd(module.name, cmd_enter_module)
    cli.repl()
