"""netcore — what the transports and analysers in this repository share.

    from netcore.rtt import RTTEstimator
    from netcore.congestion import build
    from netcore.measure import Measurement

Three things, each of which existed two or three times before: an RFC 6298
round-trip estimator, a set of congestion controllers, and a way of reporting a
latency measurement. Stdlib only, so a module importing them standalone gains
no dependencies.
"""

from .congestion import BBR, CUBIC, CongestionController, Reno, build
from .measure import Measurement, Report, Run, percentile
from .rtt import RTTEstimator

__version__ = "1.0.0"
__all__ = [
    "RTTEstimator",
    "CongestionController", "Reno", "CUBIC", "BBR", "build",
    "Measurement", "Run", "Report", "percentile",
]
