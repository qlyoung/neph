import protos.bgp

class NephFuzzer(object):
    def __init__(self, proto):
        self.proto = proto

    def run(self):
        self.proto.run()
