"""
QUIC loss detection and recovery (RFC 9002).

Key mechanisms
--------------
  Packet number spaces: Initial, Handshake and Application Data each have
  independent packet number sequences and ACK state.

  ACK-based loss detection: A packet is declared lost when a packet with a
  higher packet number is acknowledged AND the time since the packet was sent
  exceeds the reordering threshold (kTimeThreshold × max(SRTT, latest_RTT)).

  PTO (probe timeout): When no acknowledgement is received for kPTOMultiplier
  × (SRTT + 4×RTTVAR + max_ack_delay), send a probe packet to elicit an ACK.

  Congestion control: pluggable. Reno by default, matching RFC 9002's
  reference; CUBIC and BBR are available from `netcore.congestion` and can be
  selected per connection. The RTT estimator is `netcore.rtt`, shared with the
  other transport in this repository rather than reimplemented here.
"""

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path as _Path
from typing import Optional

_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from netcore.congestion import CongestionController, build as build_controller  # noqa: E402
from netcore.rtt import RTTEstimator  # noqa: E402


# ── RFC 9002 constants ────────────────────────────────────────────────────────

K_TIME_THRESHOLD     = 9 / 8     # 1.125 — reordering window multiplier
K_GRANULARITY        = 0.001     # 1 ms
K_INITIAL_RTT        = 0.333     # 333 ms initial RTT estimate
K_PTO_MULTIPLIER     = 2
K_INITIAL_WINDOW     = 10 * 1200 # 10 × max_datagram_size
K_MINIMUM_WINDOW     = 2 * 1200
K_LOSS_REDUCTION     = 0.5
MAX_ACK_DELAY        = 0.025     # 25 ms


@dataclass
class SentPacket:
    pn:           int
    sent_at:      float
    in_flight:    bool
    acked:        bool   = False
    lost:         bool   = False
    size:         int    = 0
    frames:       list   = field(default_factory=list)


class PacketNumberSpace:
    """Independent PN space: one of Initial, Handshake or Application."""

    def __init__(self) -> None:
        self.next_pn:    int              = 0
        self.largest_acked: int           = -1
        self.sent:       dict[int, SentPacket] = {}
        self.ack_eliciting_in_flight: int  = 0
        self.loss_time: Optional[float]   = None

    def on_packet_sent(self, pn: int, size: int, in_flight: bool, frames: list) -> None:
        self.sent[pn] = SentPacket(
            pn=pn, sent_at=time.monotonic(),
            in_flight=in_flight, size=size, frames=frames,
        )
        if in_flight:
            self.ack_eliciting_in_flight += 1

    def allocate_pn(self) -> int:
        pn = self.next_pn
        self.next_pn += 1
        return pn


class RecoveryManager:
    """
    Tracks all three packet number spaces and drives loss detection.

    Simplified: no ECN, no per-space PTO backoff complexity.
    """

    SPACES = ("initial", "handshake", "app")

    def __init__(self, congestion: str | CongestionController = "reno") -> None:
        self.spaces: dict[str, PacketNumberSpace] = {
            s: PacketNumberSpace() for s in self.SPACES
        }

        # One RTT estimator across all three spaces, per RFC 9002 §5.
        self.rtt = RTTEstimator(
            granularity=K_GRANULARITY,
            max_ack_delay=MAX_ACK_DELAY,
            initial_rtt=K_INITIAL_RTT,
            # RFC 9002's initial PTO: srtt + 4·rttvar + max_ack_delay with
            # rttvar seeded at half the initial RTT.
            initial_rto=K_INITIAL_RTT * 3 + MAX_ACK_DELAY,
        )

        # Congestion control is a seam: Reno is the RFC 9002 reference, and
        # CUBIC or BBR can be dropped in without touching loss detection.
        self.congestion: CongestionController = (
            build_controller(congestion, mss=1200, initial_window=K_INITIAL_WINDOW)
            if isinstance(congestion, str) else congestion
        )
        self.bytes_in_flight: int = 0

        self._congestion_recovery_start: Optional[float] = None

        # PTO tracking
        self._pto_count: int = 0

    # ── RTT ───────────────────────────────────────────────────────────────────

    def update_rtt(self, latest_rtt: float, ack_delay: float = 0.0) -> None:
        self.rtt.update(latest_rtt, ack_delay=ack_delay)

    # The estimator owns these now; kept as properties because loss detection
    # and every caller read them by name.

    @property
    def srtt(self) -> float:
        return self.rtt.smoothed

    @property
    def _srtt(self) -> float:
        return self.rtt.smoothed

    @property
    def _rttvar(self) -> float:
        return self.rtt.rttvar

    @property
    def _latest_rtt(self) -> float:
        return self.rtt.latest_rtt

    @property
    def cwnd(self) -> int:
        return self.congestion.cwnd

    @cwnd.setter
    def cwnd(self, value: int) -> None:
        self.congestion.cwnd = int(value)

    @property
    def ssthresh(self) -> int:
        return getattr(self.congestion, "ssthresh", 2 ** 30)

    @ssthresh.setter
    def ssthresh(self, value: int) -> None:
        if hasattr(self.congestion, "ssthresh"):
            self.congestion.ssthresh = int(value)

    @property
    def rto(self) -> float:
        """Retransmission timeout (PTO) in seconds."""
        return self.rtt.rto

    # ── on_ack_received ───────────────────────────────────────────────────────

    def on_ack_received(
        self,
        space: str,
        largest_acked: int,
        ack_delay: float,
        acked_ranges: list[tuple[int, int]],
    ) -> tuple[list[SentPacket], list[SentPacket]]:
        """
        Process an ACK frame.

        acked_ranges is a list of (start, end) inclusive packet number ranges.

        Returns (newly_acked, lost_packets).
        """
        ns = self.spaces[space]
        newly_acked: list[SentPacket] = []

        for start, end in acked_ranges:
            for pn in range(start, end + 1):
                if pn in ns.sent and not ns.sent[pn].acked:
                    pkt = ns.sent[pn]
                    pkt.acked = True
                    newly_acked.append(pkt)
                    if pkt.in_flight:
                        self.bytes_in_flight -= pkt.size
                        ns.ack_eliciting_in_flight -= 1
                        self._on_packet_acked(pkt)

        if newly_acked:
            if largest_acked == max(p.pn for p in newly_acked):
                pkt = ns.sent.get(largest_acked)
                if pkt and not pkt.lost:
                    self.update_rtt(time.monotonic() - pkt.sent_at, ack_delay)

        if largest_acked > ns.largest_acked:
            ns.largest_acked = largest_acked

        self._pto_count = 0
        lost = self._detect_lost_packets(space)
        return newly_acked, lost

    def _on_packet_acked(self, pkt: SentPacket) -> None:
        # Window growth belongs to the controller, which may not be Reno.
        self.congestion.on_ack(pkt.size, self.rtt.latest_rtt)

    # ── loss detection ────────────────────────────────────────────────────────

    def _detect_lost_packets(self, space: str) -> list[SentPacket]:
        ns           = self.spaces[space]
        lost: list[SentPacket] = []
        now          = time.monotonic()
        loss_delay   = K_TIME_THRESHOLD * max(self._srtt, self._latest_rtt)
        loss_delay   = max(loss_delay, K_GRANULARITY)

        for pkt in list(ns.sent.values()):
            if pkt.acked or pkt.lost:
                continue
            if pkt.pn > ns.largest_acked:
                continue
            if (ns.largest_acked - pkt.pn >= 3 or
                    now - pkt.sent_at >= loss_delay):
                pkt.lost = True
                lost.append(pkt)
                if pkt.in_flight:
                    self.bytes_in_flight -= pkt.size
                    ns.ack_eliciting_in_flight -= 1
                    self._on_congestion_event(pkt.sent_at)

        return lost

    def _on_congestion_event(self, sent_at: float) -> None:
        """Reduce the window once per recovery epoch, whatever the controller.

        Several packets are usually declared lost from one event; reducing once
        per lost packet would collapse the window. `_congestion_recovery_start`
        is the epoch boundary — losses sent before it are already accounted
        for.
        """
        if (self._congestion_recovery_start is not None
                and sent_at <= self._congestion_recovery_start):
            return

        self._congestion_recovery_start = time.monotonic()
        self.congestion.on_loss()
        # RFC 9002 sizes the reduction from bytes in flight, not from cwnd, and
        # floors it at the minimum window. Reno's own on_loss halves cwnd; for
        # a loss-based controller apply the RFC's floor on top.
        if hasattr(self.congestion, "ssthresh"):
            self.congestion.ssthresh = max(
                min(self.congestion.ssthresh,
                    max(int(self.bytes_in_flight * K_LOSS_REDUCTION), K_MINIMUM_WINDOW)),
                K_MINIMUM_WINDOW,
            )
            self.congestion.cwnd = max(self.congestion.ssthresh, K_MINIMUM_WINDOW)
        else:
            self.congestion.cwnd = max(self.congestion.cwnd, K_MINIMUM_WINDOW)

    # ── PTO ───────────────────────────────────────────────────────────────────

    def pto_expired(self, space: str) -> bool:
        ns = self.spaces[space]
        if ns.ack_eliciting_in_flight == 0:
            return False
        now = time.monotonic()
        for pkt in ns.sent.values():
            if not pkt.acked and not pkt.lost and pkt.in_flight:
                elapsed = now - pkt.sent_at
                if elapsed > self.rto * (2 ** self._pto_count):
                    return True
        return False

    def on_pto_fired(self) -> None:
        self._pto_count += 1

    # ── ACK frame builder ─────────────────────────────────────────────────────

    def build_ack_ranges(self, space: str) -> tuple[int, int, list]:
        """
        Build ACK frame parameters from the set of acked PNs.

        Returns (largest_acked, first_ack_range, additional_ranges).
        """
        from .frames import AckRange
        ns   = self.spaces[space]
        acked_pns = sorted(
            (pn for pn, p in ns.sent.items() if p.acked), reverse=True
        )
        if not acked_pns:
            return 0, 0, []

        largest   = acked_pns[0]
        runs: list[tuple[int, int]] = []
        start = end = acked_pns[0]

        for pn in acked_pns[1:]:
            if pn == end - 1:
                end = pn
            else:
                runs.append((start, end))
                start = end = pn
        runs.append((start, end))

        first_range = runs[0][0] - runs[0][1]
        extra: list[AckRange] = []
        for i in range(1, len(runs)):
            gap = runs[i - 1][1] - runs[i][0] - 1
            ack = runs[i][0] - runs[i][1]
            extra.append(AckRange(gap=gap, ack=ack))

        return largest, first_range, extra
