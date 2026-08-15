"""
SendWindow  — tracks in-flight segments, advances on ACK, identifies timeouts.
RecvBuffer  — reorders out-of-order segments and delivers data in sequence.

Sequence numbers are byte offsets in a 2^32 space (wrap-around handled
with the half-space comparison helpers at the bottom of this module).
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .packet import SEQ_SPACE


# ── sequence-number arithmetic ─────────────────────────────────────────────────

def seq_lt(a: int, b: int) -> bool:
    """True if a is strictly before b in the sequence-number space."""
    return ((b - a) % SEQ_SPACE) < (SEQ_SPACE // 2)


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


# ── send window ────────────────────────────────────────────────────────────────

@dataclass
class _Seg:
    seq:     int
    data:    bytes
    sent_at: float = field(default_factory=time.monotonic)
    retries: int   = 0


class SendWindow:
    """
    Sliding send window with selective retransmission support.

    The window is expressed in bytes.  The caller must check
    inflight_bytes() against the congestion window before pushing new data.
    """

    def __init__(self, isn: int = 0) -> None:
        self._base:     int           = isn
        self._next:     int           = isn
        self._segs:     dict[int, _Seg] = {}
        self._lock       = threading.Lock()
        self._dup_count: int          = 0
        self._last_ack:  int          = isn

    @property
    def base(self) -> int:
        return self._base

    @property
    def next_seq(self) -> int:
        return self._next

    def inflight_bytes(self) -> int:
        with self._lock:
            return sum(len(s.data) for s in self._segs.values())

    def push(self, data: bytes) -> int:
        """Assign a sequence number and store the segment. Returns seq."""
        with self._lock:
            seq = self._next
            self._segs[seq] = _Seg(seq=seq, data=data)
            self._next = (self._next + len(data)) % SEQ_SPACE
            return seq

    def ack(
        self,
        ack_num: int,
        rtt_cb: Optional[Callable[[float], None]] = None,
    ) -> tuple[int, bool]:
        """
        Process a cumulative ACK.

        Returns (newly_acked_bytes, is_duplicate).
        rtt_cb is called with the RTT sample for non-retransmitted segments
        (Karn's algorithm).
        """
        with self._lock:
            if ack_num == self._last_ack:
                self._dup_count += 1
                return 0, True

            if seq_le(ack_num, self._base) and ack_num != self._last_ack:
                return 0, True

            newly_acked = 0
            to_remove   = []
            for seq, seg in self._segs.items():
                end = (seq + len(seg.data)) % SEQ_SPACE
                if seq_le(end, ack_num):
                    newly_acked += len(seg.data)
                    if rtt_cb is not None and seg.retries == 0:
                        rtt_cb(time.monotonic() - seg.sent_at)
                    to_remove.append(seq)

            for seq in to_remove:
                del self._segs[seq]

            self._base      = ack_num
            self._last_ack  = ack_num
            self._dup_count = 0
            return newly_acked, False

    @property
    def dup_ack_count(self) -> int:
        return self._dup_count

    def timed_out(self, rto: float) -> list[_Seg]:
        """Return segments that have been in-flight longer than rto seconds."""
        now = time.monotonic()
        with self._lock:
            return [s for s in self._segs.values() if (now - s.sent_at) > rto]

    def mark_retransmit(self, seq: int) -> None:
        with self._lock:
            if seq in self._segs:
                seg = self._segs[seq]
                seg.sent_at = time.monotonic()
                seg.retries += 1

    def get(self, seq: int) -> Optional[_Seg]:
        with self._lock:
            return self._segs.get(seq)


# ── receive buffer ─────────────────────────────────────────────────────────────

class RecvBuffer:
    """
    In-order delivery buffer.

    Segments that arrive out of order are held in _ooo until the gap is
    filled.  read() blocks the calling thread until data is available.
    """

    def __init__(self, isn: int = 0) -> None:
        self._next:  int           = isn
        self._ooo:   dict[int, bytes] = {}
        self._data:  bytearray     = bytearray()
        self._lock   = threading.Lock()
        self._ready  = threading.Event()
        self._closed = False

    @property
    def next_expected(self) -> int:
        return self._next

    def receive(self, seq: int, data: bytes) -> bool:
        """
        Accept a segment.  Returns True if it contributed new bytes.
        Duplicate and already-covered segments are silently discarded.
        """
        if not data:
            return False

        with self._lock:
            end = (seq + len(data)) % SEQ_SPACE

            # Completely before the receive pointer — duplicate
            if seq_le(end, self._next):
                return False

            if seq == self._next:
                self._data.extend(data)
                self._next = end
                # Drain any now-contiguous buffered segments
                while self._next in self._ooo:
                    chunk      = self._ooo.pop(self._next)
                    self._data.extend(chunk)
                    self._next = (self._next + len(chunk)) % SEQ_SPACE
                self._ready.set()
            else:
                self._ooo[seq] = data

        return True

    def read(self, n: int, timeout: float = 30.0) -> bytes:
        """Block until up to n bytes are available or timeout expires."""
        if not self._data:
            if not self._ready.wait(timeout):
                return b""
        with self._lock:
            chunk = bytes(self._data[:n])
            del self._data[:n]
            if not self._data:
                self._ready.clear()
            return chunk

    def close(self) -> None:
        self._closed = True
        self._ready.set()

    def available(self) -> int:
        with self._lock:
            return len(self._data)
