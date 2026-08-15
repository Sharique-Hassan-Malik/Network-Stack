"""Congestion control, once, for every transport in this repository.

Three algorithms behind one interface:

  Reno   — the classic loss-based AIMD window. What QUIC's recovery manager
           implemented inline, extracted so it can be swapped.
  CUBIC  — RFC 8312. Window follows a cubic function of time since the last
           congestion event, which recovers faster than Reno on fat pipes.
  BBR    — model-based. Estimates bottleneck bandwidth and round-trip
           propagation time and targets their product, so it is not driven by
           loss at all.

Before this file, the reliable-transport module had CUBIC and BBR and the QUIC
module had a Reno it could not swap out. They now draw from the same set: QUIC
gained two algorithms it never had, and there is one implementation of each to
be correct in.

Every controller exposes the same three things — `cwnd`, `on_ack`, `on_loss` —
so a transport can be handed any of them without knowing which. Stdlib only.
"""

from __future__ import annotations

import inspect
from typing import Callable, Protocol, runtime_checkable


@runtime_checkable
class CongestionController(Protocol):
    """What a transport needs from a congestion controller, and nothing more."""

    cwnd: int

    def on_ack(self, acked_bytes: int, rtt: float) -> None: ...
    def on_loss(self) -> None: ...


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

    def __init__(
        self,
        mss: int = 1400,
        initial_window: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.mss = mss
        # BBR's state machine is driven by elapsed time, so it cannot be
        # stepped by a simulation that does not advance the wall clock. The
        # clock is injectable for exactly that reason.
        self._clock = clock

        self._bw_filter:     deque[float] = deque(maxlen=_BW_WINDOW_ROUNDS)
        self._min_rtt:       float        = float("inf")
        self._min_rtt_stamp: float        = 0.0

        self._state:        str   = "STARTUP"
        self._pacing_gain:  float = _STARTUP_GAIN
        self._cwnd_gain:    float = 2.0
        self._cycle_idx:    int   = 0
        self._state_stamp:  float = clock()

        self._delivered:       int   = 0
        self._delivered_stamp: float = clock()
        self._last_bw:         float = 0.0
        self._no_growth:       int   = 0

        self.cwnd: int = (
            initial_window if initial_window is not None else mss * _MIN_CWND_PKTS * 2
        )

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
        now = self._clock()
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

    def __init__(
        self,
        mss: int = 1400,
        initial_window: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.mss   = mss
        self._clock = clock
        self.cwnd: int = initial_window if initial_window is not None else mss * 10
        self._ssthresh: int    = 2 ** 30
        self._w_max:    float  = 0.0
        self._k:        float  = 0.0
        self._t_epoch:  float  = clock()
        self._slow_start: bool = True

    @property
    def pacing_rate(self) -> float:
        return float("inf")   # window-based; no per-packet pacing

    def on_ack(self, acked_bytes: int, rtt: float = 0.0) -> None:
        if self._slow_start:
            self.cwnd += acked_bytes
            if self.cwnd >= self._ssthresh:
                self._slow_start = False
        else:
            t      = self._clock() - self._t_epoch
            w_cubic = _C * (t - self._k) ** 3 + self._w_max
            self.cwnd = max(int(w_cubic), self.mss)

    def on_loss(self) -> None:
        self._w_max      = float(self.cwnd)
        self._ssthresh   = max(int(self.cwnd * _BETA), 2 * self.mss)
        self.cwnd        = self._ssthresh
        self._k          = (self._w_max * (1 - _BETA) / _C) ** (1.0 / 3.0)
        self._t_epoch    = self._clock()
        self._slow_start = False


# ── Reno ───────────────────────────────────────────────────────────────────────

_RENO_LOSS_REDUCTION = 0.5
_RENO_MIN_CWND_PKTS = 2


class Reno:
    """Classic AIMD: exponential in slow start, additive after, halve on loss.

    `on_loss_at` exists because a transport that detects several packets lost
    from one event must not halve the window several times. Losses from before
    the current recovery epoch are ignored, which is what RFC 9002 calls being
    in recovery.
    """

    def __init__(self, mss: int = 1400, initial_window: int | None = None) -> None:
        self.mss = mss
        self.cwnd: int = initial_window if initial_window is not None else mss * 10
        self.ssthresh: int = 2 ** 30
        self._recovery_epoch: float = 0.0

    @property
    def pacing_rate(self) -> float:
        return float("inf")          # window-based; no per-packet pacing

    @property
    def in_slow_start(self) -> bool:
        return self.cwnd < self.ssthresh

    def on_ack(self, acked_bytes: int, rtt: float = 0.0) -> None:
        if self.in_slow_start:
            self.cwnd += acked_bytes
        else:
            self.cwnd += max(1, int(self.mss * acked_bytes / max(self.cwnd, 1)))

    def on_loss(self) -> None:
        self.ssthresh = max(int(self.cwnd * _RENO_LOSS_REDUCTION),
                            _RENO_MIN_CWND_PKTS * self.mss)
        self.cwnd = self.ssthresh

    def on_loss_at(self, sent_at: float, now: float) -> bool:
        """Halve the window unless this loss belongs to the epoch already handled.

        Returns whether the window was actually reduced.
        """
        if sent_at <= self._recovery_epoch:
            return False
        self._recovery_epoch = now
        self.on_loss()
        return True


CONTROLLERS = {"reno": Reno, "cubic": CUBIC, "bbr": BBR}

# Every option any controller accepts, so a typo is still caught.
_ALL_OPTIONS = {
    name
    for factory in CONTROLLERS.values()
    for name in inspect.signature(factory).parameters
} - {"self", "mss"}


def build(name: str = "cubic", mss: int = 1400, **options) -> CongestionController:
    """Construct a controller by name, so it can be chosen from a CLI flag.

    Options a given controller does not take are dropped rather than raising:
    only the time-driven algorithms accept `clock`, and a caller configuring
    several at once should not have to know which. Passing an option no
    controller accepts is still an error.
    """
    try:
        factory = CONTROLLERS[name.lower()]
    except KeyError:
        raise ValueError(
            f"unknown congestion controller {name!r}; "
            f"choose from {', '.join(sorted(CONTROLLERS))}"
        ) from None

    accepted = set(inspect.signature(factory).parameters)
    unknown = set(options) - _ALL_OPTIONS
    if unknown:
        raise TypeError(
            f"no congestion controller accepts {', '.join(sorted(unknown))}"
        )
    return factory(mss=mss, **{k: v for k, v in options.items() if k in accepted})
