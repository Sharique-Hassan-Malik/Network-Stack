"""
Round-trip time estimation per RFC 6298.

Uses exponentially-weighted moving averages for SRTT and RTTVAR
with Karn's algorithm (exclude retransmitted segments from samples)
applied by the caller.
"""


class RTTEstimator:
    ALPHA   = 0.125
    BETA    = 0.25
    K       = 4
    MIN_RTO = 0.2
    MAX_RTO = 60.0

    def __init__(self) -> None:
        self._srtt:   float | None = None
        self._rttvar: float        = 0.0
        self._rto:    float        = 1.0

    @property
    def rto(self) -> float:
        return self._rto

    @property
    def srtt(self) -> float:
        return self._srtt if self._srtt is not None else 1.0

    def update(self, sample: float) -> None:
        if self._srtt is None:
            self._srtt   = sample
            self._rttvar = sample / 2.0
        else:
            self._rttvar = (1 - self.BETA) * self._rttvar + self.BETA * abs(self._srtt - sample)
            self._srtt   = (1 - self.ALPHA) * self._srtt + self.ALPHA * sample
        self._rto = max(self.MIN_RTO, min(self.MAX_RTO,
                                          self._srtt + self.K * self._rttvar))

    def backoff(self) -> None:
        """Exponential backoff on timeout. Capped at MAX_RTO."""
        self._rto = min(self.MAX_RTO, self._rto * 2)

    def reset_backoff(self) -> None:
        if self._srtt is not None:
            self._rto = max(self.MIN_RTO, self._srtt + self.K * self._rttvar)
