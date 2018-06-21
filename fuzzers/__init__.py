from fuzzers.fuzz import FuzzerMixin
from fuzzers.bgp import BGPFuzzer

fuzzers = [BGPFuzzer.__name__]

__all__ = fuzzers + []
