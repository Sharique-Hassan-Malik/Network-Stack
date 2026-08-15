"""
QUIC stream layer (RFC 9000 §2–§4).

Stream IDs
----------
  Client-initiated bidirectional :  0, 4, 8  …  (id mod 4 == 0)
  Server-initiated bidirectional :  1, 5, 9  …  (id mod 4 == 1)
  Client-initiated unidirectional:  2, 6, 10 …  (id mod 4 == 2)
  Server-initiated unidirectional:  3, 7, 11 …  (id mod 4 == 3)

Flow control
------------
  Two levels: per-stream (MAX_STREAM_DATA) and connection-wide (MAX_DATA).
  A stream is blocked when send_offset >= stream_limit.
  The connection is blocked when total_sent >= connection_limit.

  Initial limits are negotiated during the handshake (transport parameters).
  Receivers send MAX_DATA / MAX_STREAM_DATA frames when their buffers are drained.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Optional

from .frames import StreamFrame, MaxStreamDataFrame, MaxDataFrame


class StreamState(IntEnum):
    READY         = auto()   # created, nothing sent/received
    SEND          = auto()   # sending data
    DATA_SENT     = auto()   # FIN sent, waiting for ACK
    DATA_RECVD    = auto()   # all data and FIN acked
    RECV          = auto()   # receiving data
    SIZE_KNOWN    = auto()   # FIN received, length known
    DATA_READ     = auto()   # app has read all data
    RESET_SENT    = auto()
    RESET_RECVD   = auto()
    CLOSED        = auto()


@dataclass
class SendStream:
    stream_id:   int
    limit:       int   = 1 << 16    # initial stream flow-control limit
    _offset:     int   = 0
    _buf:        bytearray = field(default_factory=bytearray)
    _fin_sent:   bool  = False
    _state:      StreamState = StreamState.READY
    _lock:       threading.Lock = field(default_factory=threading.Lock)

    def write(self, data: bytes) -> int:
        with self._lock:
            self._buf.extend(data)
            self._state = StreamState.SEND
            return len(data)

    def close(self) -> None:
        with self._lock:
            self._fin_sent = True

    def pending_frames(self, max_payload: int = 1200) -> list[StreamFrame]:
        """Dequeue up to max_payload bytes as StreamFrames, respecting stream limit."""
        frames: list[StreamFrame] = []
        with self._lock:
            while self._buf and self._offset < self.limit:
                can_send = min(max_payload, len(self._buf), self.limit - self._offset)
                if can_send <= 0:
                    break
                chunk = bytes(self._buf[:can_send])
                del self._buf[:can_send]
                fin = self._fin_sent and not self._buf
                frames.append(StreamFrame(
                    stream_id=self.stream_id,
                    offset=self._offset,
                    data=chunk,
                    fin=fin,
                ))
                self._offset += len(chunk)
                if fin:
                    self._state = StreamState.DATA_SENT
            if not self._buf and self._fin_sent and self._state == StreamState.SEND:
                self._state = StreamState.DATA_SENT
        return frames

    def is_blocked(self) -> bool:
        with self._lock:
            return bool(self._buf) and self._offset >= self.limit

    def update_limit(self, new_limit: int) -> None:
        with self._lock:
            if new_limit > self.limit:
                self.limit = new_limit


@dataclass
class RecvStream:
    stream_id:   int
    limit:       int   = 1 << 16
    _next_read:  int   = 0         # next byte app will read
    _highest:    int   = 0         # highest byte offset received
    _buf:        dict[int, bytes] = field(default_factory=dict)
    _fin_offset: Optional[int]    = None
    _state:      StreamState      = StreamState.RECV
    _ready:      threading.Event  = field(default_factory=threading.Event)
    _lock:       threading.Lock   = field(default_factory=threading.Lock)

    def receive(self, offset: int, data: bytes, fin: bool) -> bool:
        """
        Deliver bytes at offset.  Returns True if new data was buffered.
        """
        with self._lock:
            end = offset + len(data)
            if end > self._highest:
                self._highest = end
            if fin:
                self._fin_offset = end
                self._state      = StreamState.SIZE_KNOWN
            if offset not in self._buf and data:
                self._buf[offset] = data
                self._ready.set()
                return True
        return False

    def read(self, n: int, timeout: float = 30.0) -> bytes:
        """Block until up to n bytes are in-order available."""
        if not self._ready.wait(timeout):
            return b""
        out = bytearray()
        with self._lock:
            while len(out) < n and self._next_read in self._buf:
                chunk = self._buf.pop(self._next_read)
                take  = min(n - len(out), len(chunk))
                out.extend(chunk[:take])
                if take < len(chunk):
                    self._buf[self._next_read + take] = chunk[take:]
                self._next_read += take
            if not self._buf:
                self._ready.clear()
            if self._fin_offset is not None and self._next_read >= self._fin_offset:
                self._state = StreamState.DATA_READ
        return bytes(out)

    def should_update_limit(self, increment: int = 1 << 14) -> Optional[int]:
        """Return a new limit if window is getting low, else None."""
        with self._lock:
            consumed = self._next_read
            if self.limit - consumed < increment // 2:
                new_limit = consumed + increment
                self.limit = new_limit
                return new_limit
        return None

    def is_fin_read(self) -> bool:
        return self._state == StreamState.DATA_READ


class StreamManager:
    """
    Manages all streams for one connection.

    Parameters
    ----------
    is_server : bool
    initial_max_stream_data : int   Per-stream receive window.
    initial_max_data : int          Connection-level receive window.
    initial_max_streams : int       Max concurrent bidirectional streams.
    """

    def __init__(
        self,
        is_server: bool = False,
        initial_max_stream_data: int = 1 << 16,
        initial_max_data: int        = 1 << 20,
        initial_max_streams: int     = 100,
    ) -> None:
        self._is_server              = is_server
        self._max_stream_data        = initial_max_stream_data
        self._max_data               = initial_max_data
        self._max_streams            = initial_max_streams

        self._send_streams: dict[int, SendStream] = {}
        self._recv_streams: dict[int, RecvStream] = {}

        # Connection-level flow control
        self._conn_send_offset:  int = 0
        self._conn_send_limit:   int = initial_max_data
        self._conn_recv_total:   int = 0

        self._next_local_bidi:  int = 1 if is_server else 0
        self._next_local_uni:   int = 3 if is_server else 2

        self._lock = threading.Lock()

    # ── stream creation ───────────────────────────────────────────────────────

    def open_bidi_stream(self) -> SendStream:
        with self._lock:
            sid = self._next_local_bidi
            self._next_local_bidi += 4
            s = SendStream(stream_id=sid, limit=self._max_stream_data)
            self._send_streams[sid] = s
            return s

    def open_uni_stream(self) -> SendStream:
        with self._lock:
            sid = self._next_local_uni
            self._next_local_uni += 4
            s = SendStream(stream_id=sid, limit=self._max_stream_data)
            self._send_streams[sid] = s
            return s

    def get_or_create_recv(self, stream_id: int) -> RecvStream:
        with self._lock:
            if stream_id not in self._recv_streams:
                self._recv_streams[stream_id] = RecvStream(
                    stream_id=stream_id,
                    limit=self._max_stream_data,
                )
            return self._recv_streams[stream_id]

    # ── flow control frames ───────────────────────────────────────────────────

    def flow_control_frames(self) -> list:
        frames = []

        # Connection-level window update
        if self._conn_send_limit - self._conn_send_offset < self._max_data // 4:
            new_limit = self._conn_send_offset + self._max_data
            self._conn_send_limit = new_limit
            frames.append(MaxDataFrame(maximum=new_limit))

        # Per-stream window updates
        with self._lock:
            for rs in self._recv_streams.values():
                new_lim = rs.should_update_limit(self._max_stream_data // 2)
                if new_lim is not None:
                    frames.append(MaxStreamDataFrame(stream_id=rs.stream_id, maximum=new_lim))

        return frames

    def update_stream_limit(self, stream_id: int, limit: int) -> None:
        with self._lock:
            if stream_id in self._send_streams:
                self._send_streams[stream_id].update_limit(limit)

    def update_connection_limit(self, limit: int) -> None:
        if limit > self._conn_send_limit:
            self._conn_send_limit = limit

    def on_stream_data_received(self, frame: StreamFrame) -> None:
        rs = self.get_or_create_recv(frame.stream_id)
        rs.receive(frame.offset, frame.data, frame.fin)
        self._conn_recv_total += len(frame.data)

    def pending_send_frames(self, conn_budget: int) -> list[StreamFrame]:
        """Gather StreamFrames from all send streams within the connection budget."""
        frames: list[StreamFrame] = []
        remaining = min(conn_budget, self._conn_send_limit - self._conn_send_offset)
        with self._lock:
            streams = list(self._send_streams.values())
        for stream in streams:
            if remaining <= 0:
                break
            sf = stream.pending_frames(max_payload=min(1200, remaining))
            for f in sf:
                self._conn_send_offset += len(f.data)
                remaining -= len(f.data)
            frames.extend(sf)
        return frames
