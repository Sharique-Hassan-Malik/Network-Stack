"""RTT estimation for this transport — the shared implementation.

RFC 6298 used to be implemented here and again, separately, inside the QUIC
module's recovery manager, with the same constants and different framing. Both
now use `netcore.rtt`. Re-exported so `from ctp.rtt import RTTEstimator` keeps
working.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from netcore.rtt import ALPHA, BETA, K, MAX_RTO, MIN_RTO, RTTEstimator  # noqa: E402

__all__ = ["RTTEstimator", "ALPHA", "BETA", "K", "MIN_RTO", "MAX_RTO"]
