from nephcli import NephCLI
from .. import protos

class BgpCLI(NephCLI):
    def __init__(self):
        super().__init__()
        self.prompt = "(bgp)>>"

def cmd_bgp(cmd):
    n = prompt("neighbor: ")
    my_as = prompt("local as: ")
    bgp_id = prompt("bgp_id: ")

    b = BGP(neighbor=n, my_as=int(my_as), bgp_id=bgp_id)
    b.run()

def repl():
    cli = BgpCLI()
    cli.add_cmd("fuzzopen", cmd_bgp)
    cli.repl()
