"""
Two congestion control algorithms:

  BBR   — model-based; estimates bottleneck bandwidth (BtlBw) and round-trip
           propagation time (RTprop) to derive a pacing rate and cwnd.
           States: STARTUP → DRAIN → PROBE_BW ↔ PROBE_RTT.

  CUBIC — loss-based (RFC 8312); window follows a cubic function of time
           since the last congestion event.  Included as a comparison target
           for the benchmark.
"""

import time
from collections import deque

# ── BBR constants ──────────────────────────────────────────────────────────────
_STARTUP_GAIN     = 2.885              # ≈ 2/ln(2); doubles estimated BW each RTT
_DRAIN_GAIN       = 1.0 / _STARTUP_GAIN
_PROBE_BW_CYCLE   = (1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0)
_BW_WINDOW_ROUNDS = 10                 # bandwidth filter depth
_MIN_CWND_PKTS    = 4


class BBR:
    """
    Simplified BBR congestion control.

    The core idea: keep inflight data ≈ BtlBw × RTprop (the bandwidth-delay
    product).  Periodically probe upward (+25 % gain) then drain the queue
    (−25 % gain) to track changes in the bottleneck.
    """

    def __init__(self, mss: int = 1400) -> None:
        self.mss = mss

        self._bw_filter:     deque[float] = deque(maxlen=_BW_WINDOW_ROUNDS)
        self._min_rtt:       float        = float("inf")
        self._min_rtt_stamp: float        = 0.0

        self._state:        str   = "STARTUP"
        self._pacing_gain:  float = _STARTUP_GAIN
        self._cwnd_gain:    float = 2.0
        self._cycle_idx:    int   = 0
        self._state_stamp:  float = time.monotonic()

        self._delivered:       int   = 0
        self._delivered_stamp: float = time.monotonic()
        self._last_bw:         float = 0.0
        self._no_growth:       int   = 0

        self.cwnd: int = mss * _MIN_CWND_PKTS * 2

    # ── read-only properties ───────────────────────────────────────────────────

    @property
    def btl_bw(self) -> float:
        return max(self._bw_filter) if self._bw_filter else 0.0

    @property
    def rt_prop(self) -> float:
        return self._min_rtt if self._min_rtt != float("inf") else 0.05

    @property
    def pacing_rate(self) -> float:
        bw = self.btl_bw
        if bw <= 0:
            return float(self.mss) * 100   # bootstrap: 100 MSS/s
        return max(self._pacing_gain * bw, float(self.mss))

    # ── callbacks ──────────────────────────────────────────────────────────────

    def on_ack(self, acked_bytes: int, rtt: float) -> None:
        now = time.monotonic()
        self._delivered += acked_bytes

        elapsed = now - self._delivered_stamp
        if elapsed > 1e-6 and acked_bytes > 0:
            self._bw_filter.append(acked_bytes / elapsed)
            self._delivered_stamp = now

        if rtt < self._min_rtt:
            self._min_rtt       = rtt
            self._min_rtt_stamp = now

        self._update_state(now)
        self._update_cwnd()

    def on_loss(self) -> None:
        # BBR is not driven by loss, but reduce cwnd conservatively on timeout.
        self.cwnd = max(self.cwnd // 2, _MIN_CWND_PKTS * self.mss)

    # ── internals ─────────────────────────────────────────────────────────────

    def _update_state(self, now: float) -> None:
        bw = self.btl_bw

        if self._state == "STARTUP":
            if bw > 0 and self._last_bw > 0:
                if bw / self._last_bw < 1.25:
                    self._no_growth += 1
                else:
                    self._no_growth = 0
            self._last_bw = bw
            if self._no_growth >= 3:
                self._state       = "DRAIN"
                self._pacing_gain = _DRAIN_GAIN
                self._state_stamp = now

        elif self._state == "DRAIN":
            bdp = (bw * self.rt_prop) if bw > 0 else self.mss
            if self.cwnd <= int(bdp) or (now - self._state_stamp) > 2 * self.rt_prop:
                self._enter_probe_bw(now)

        elif self._state == "PROBE_BW":
            period = max(self.rt_prop, 0.05)
            if now - self._state_stamp >= period:
                self._cycle_idx   = (self._cycle_idx + 1) % len(_PROBE_BW_CYCLE)
                self._pacing_gain = _PROBE_BW_CYCLE[self._cycle_idx]
                self._state_stamp = now
            if now - self._min_rtt_stamp > 10.0:
                self._state        = "PROBE_RTT"
                self._pacing_gain  = 0.75
                self._state_stamp  = now

        elif self._state == "PROBE_RTT":
            if now - self._state_stamp >= 0.2:
                self._min_rtt_stamp = now
                self._enter_probe_bw(now)

    def _enter_probe_bw(self, now: float) -> None:
        self._state       = "PROBE_BW"
        self._cwnd_gain   = 2.0
        self._pacing_gain = _PROBE_BW_CYCLE[0]
        self._cycle_idx   = 0
        self._state_stamp = now

    def _update_cwnd(self) -> None:
        bw = self.btl_bw
        if bw <= 0:
            return
        bdp    = int(bw * self.rt_prop)
        target = max(int(self._cwnd_gain * bdp), _MIN_CWND_PKTS * self.mss)
        self.cwnd = target


# ── CUBIC ──────────────────────────────────────────────────────────────────────

_C    = 0.4
_BETA = 0.7


class CUBIC:
    """
    CUBIC congestion control (RFC 8312).

    Window function:  W(t) = C × (t − K)³ + W_max
    where K = (W_max × (1 − β) / C)^(1/3) and t is seconds since last event.
    """

    def __init__(self, mss: int = 1400) -> None:
        self.mss   = mss
        self.cwnd: int = mss * 10
        self._ssthresh: int    = 2 ** 30
        self._w_max:    float  = 0.0
        self._k:        float  = 0.0
        self._t_epoch:  float  = time.monotonic()
        self._slow_start: bool = True

    @property
    def pacing_rate(self) -> float:
        return float("inf")   # window-based; no per-packet pacing

    def on_ack(self, acked_bytes: int, rtt: float) -> None:
        if self._slow_start:
            self.cwnd += acked_bytes
            if self.cwnd >= self._ssthresh:
                self._slow_start = False
        else:
            t      = time.monotonic() - self._t_epoch
            w_cubic = _C * (t - self._k) ** 3 + self._w_max
            self.cwnd = max(int(w_cubic), self.mss)

    def on_loss(self) -> None:
        self._w_max      = float(self.cwnd)
        self._ssthresh   = max(int(self.cwnd * _BETA), 2 * self.mss)
        self.cwnd        = self._ssthresh
        self._k          = (self._w_max * (1 - _BETA) / _C) ** (1.0 / 3.0)
        self._t_epoch    = time.monotonic()
        self._slow_start = False
