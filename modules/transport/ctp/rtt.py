"""RTT estimation for this transport — the shared implementation.

RFC 6298 is one algorithm, and both this transport and the QUIC module's
recovery manager need it. It lives in `netcore.rtt` and is re-exported here, so
`from ctp.rtt import RTTEstimator` resolves to the shared estimator rather than
a second copy with the same constants and different framing.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from netcore.rtt import ALPHA, BETA, K, MAX_RTO, MIN_RTO, RTTEstimator  # noqa: E402

__all__ = ["RTTEstimator", "ALPHA", "BETA", "K", "MIN_RTO", "MAX_RTO"]
