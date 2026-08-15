"""One round-trip time estimator, for every transport in this repository.

Both stacks here implemented RFC 6298 independently and arrived at the same
constants — α=1/8, β=1/4, K=4 — with different framing. The QUIC one also
handled the peer's reported ack delay and a clock-granularity floor, which the
plain one did not; the plain one had explicit Karn backoff, which QUIC's did
not. Neither was wrong. Keeping two of them was.

This is the union: ack delay and granularity are optional and default to the
values that make the estimator behave exactly like RFC 6298 without them.
Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# RFC 6298 §2. These are not tuning knobs; changing them changes the protocol.
ALPHA = 0.125            # SRTT smoothing
BETA = 0.25              # RTTVAR smoothing
K = 4                    # RTTVAR multiplier in the RTO

MIN_RTO = 0.2            # RFC 6298 says 1s; 200ms is what deployed stacks use
MAX_RTO = 60.0


@dataclass
class RTTEstimator:
    """Smoothed RTT, variance, and the retransmission timeout derived from them.

    Parameters
    ----------
    granularity:
        Clock granularity floor applied to RTTVAR's contribution. QUIC requires
        it (RFC 9002 §5.3); a plain RFC 6298 stack leaves it at zero.
    max_ack_delay:
        Added to the RTO for protocols where the peer may delay acknowledgement
        deliberately. Zero for protocols that ack immediately.
    initial_rtt:
        Used until the first sample arrives.
    initial_rto:
        The timeout to use before any sample exists. RFC 6298 §2.1 says one
        second; QUIC derives ~1s from its initial RTT and ack delay. It is a
        parameter rather than a computation because the two RFCs state it
        differently and both are right for their protocol.
    """

    granularity: float = 0.0
    max_ack_delay: float = 0.0
    initial_rtt: float = 0.333        # RFC 9002's recommended initial RTT
    initial_rto: float = 1.0          # RFC 6298 §2.1

    srtt: float | None = field(default=None, init=False)
    rttvar: float = field(default=0.0, init=False)
    latest_rtt: float = field(default=0.0, init=False)
    min_rtt: float = field(default=float("inf"), init=False)
    samples: int = field(default=0, init=False)
    _backoff: int = field(default=0, init=False)

    # Exposed on the class because callers bound-check against them.
    MIN_RTO = MIN_RTO
    MAX_RTO = MAX_RTO

    # -- reads ---------------------------------------------------------------

    @property
    def smoothed(self) -> float:
        """SRTT, or the initial estimate before the first sample."""
        return self.initial_rtt if self.srtt is None else self.srtt

    @property
    def rto(self) -> float:
        """Retransmission timeout, including any exponential backoff in force."""
        if self.srtt is None:
            base = self.initial_rto
        else:
            base = self.smoothed + max(K * self.rttvar, self.granularity) + self.max_ack_delay
        return min(MAX_RTO, max(MIN_RTO, base) * (2 ** self._backoff))

    # -- writes --------------------------------------------------------------

    def update(self, sample: float, ack_delay: float = 0.0) -> None:
        """Fold in one RTT sample.

        Karn's algorithm — never sample a retransmitted segment — is the
        caller's responsibility, because only the caller knows whether the
        segment was sent once.
        """
        if sample <= 0:
            return

        self.latest_rtt = sample
        self.min_rtt = min(self.min_rtt, sample)
        self.samples += 1

        # Subtracting the peer's reported delay is only safe down to min_rtt:
        # a peer that over-reports would otherwise drive SRTT below anything
        # physically observed.
        adjusted = sample
        if ack_delay and sample - ack_delay >= self.min_rtt:
            adjusted = sample - min(ack_delay, self.max_ack_delay or ack_delay)

        if self.srtt is None:
            self.srtt = adjusted
            self.rttvar = adjusted / 2.0
        else:
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - adjusted)
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * adjusted

        self._backoff = 0

    def on_timeout(self) -> None:
        """Exponential backoff, capped. Cleared by the next accepted sample."""
        self._backoff = min(self._backoff + 1, 6)

    def reset_backoff(self) -> None:
        self._backoff = 0

    # Karn's algorithm calls this "backoff"; RFC 9002 calls the same thing a
    # PTO expiry. Both names work.
    backoff = on_timeout

    def to_dict(self) -> dict[str, float]:
        return {
            "srtt_ms": round(self.smoothed * 1000, 3),
            "rttvar_ms": round(self.rttvar * 1000, 3),
            "min_rtt_ms": round(self.min_rtt * 1000, 3) if self.samples else 0.0,
            "rto_ms": round(self.rto * 1000, 3),
            "samples": self.samples,
        }
