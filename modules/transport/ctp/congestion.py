"""Congestion control for this transport — the shared implementations.

BBR and CUBIC used to live here. They now live in `netcore.congestion`,
alongside the Reno that the QUIC module had inlined into its recovery manager,
so all three transports draw from one set. Re-exported here so
`from ctp.congestion import BBR` keeps working.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from netcore.congestion import (  # noqa: E402
    _BETA,
    _C,
    _MIN_CWND_PKTS,
    _PROBE_BW_CYCLE,
    _STARTUP_GAIN,
    BBR,
    CUBIC,
    CongestionController,
    Reno,
    build,
)

__all__ = [
    "BBR", "CUBIC", "Reno", "CongestionController", "build",
    "_C", "_BETA", "_STARTUP_GAIN", "_PROBE_BW_CYCLE", "_MIN_CWND_PKTS",
]
