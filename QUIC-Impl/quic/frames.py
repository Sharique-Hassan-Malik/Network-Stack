"""
QUIC frame serialization and parsing (RFC 9000 §19).

Implemented frame types
-----------------------
  PADDING              §19.1
  PING                 §19.2
  ACK                  §19.3  (no ECN)
  CRYPTO               §19.6
  STREAM               §19.8  (with OFFSET, LENGTH, FIN flags)
  MAX_DATA             §19.9
  MAX_STREAM_DATA      §19.10
  MAX_STREAMS (bidi)   §19.11
  DATA_BLOCKED         §19.12
  STREAM_DATA_BLOCKED  §19.13
  CONNECTION_CLOSE     §19.19
  HANDSHAKE_DONE       §19.20
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

from .types import (
    FrameType,
    STREAM_FLAG_FIN, STREAM_FLAG_LEN, STREAM_FLAG_OFF,
    encode_varint, decode_varint,
)


# ── ACK range ─────────────────────────────────────────────────────────────────

@dataclass
class AckRange:
    gap:  int   # number of unacked packets between this range and the previous
    ack:  int   # number of consecutive acknowledged packets in this range (minus 1)


# ── frame dataclasses ─────────────────────────────────────────────────────────

@dataclass
class PaddingFrame:
    length: int = 1


@dataclass
class PingFrame:
    pass


@dataclass
class AckFrame:
    largest_acked: int
    ack_delay:     int
    first_ack_range: int             # count of packets before largest_acked that are also acked
    ranges: list[AckRange] = field(default_factory=list)


@dataclass
class CryptoFrame:
    offset: int
    data:   bytes


@dataclass
class StreamFrame:
    stream_id: int
    offset:    int
    data:      bytes
    fin:       bool = False


@dataclass
class MaxDataFrame:
    maximum: int


@dataclass
class MaxStreamDataFrame:
    stream_id: int
    maximum:   int


@dataclass
class MaxStreamsFrame:
    maximum:        int
    bidirectional:  bool = True


@dataclass
class DataBlockedFrame:
    limit: int


@dataclass
class StreamDataBlockedFrame:
    stream_id: int
    limit:     int


@dataclass
class ConnectionCloseFrame:
    error_code:    int
    frame_type:    int
    reason:        bytes = b""
    application:   bool  = False


@dataclass
class HandshakeDoneFrame:
    pass


Frame = Union[
    PaddingFrame, PingFrame, AckFrame, CryptoFrame, StreamFrame,
    MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame,
    DataBlockedFrame, StreamDataBlockedFrame,
    ConnectionCloseFrame, HandshakeDoneFrame,
]


# ── serialization ─────────────────────────────────────────────────────────────

def encode_frame(frame: Frame) -> bytes:
    if isinstance(frame, PaddingFrame):
        return bytes(frame.length)

    if isinstance(frame, PingFrame):
        return encode_varint(FrameType.PING)

    if isinstance(frame, AckFrame):
        out  = encode_varint(FrameType.ACK)
        out += encode_varint(frame.largest_acked)
        out += encode_varint(frame.ack_delay)
        out += encode_varint(len(frame.ranges))
        out += encode_varint(frame.first_ack_range)
        for r in frame.ranges:
            out += encode_varint(r.gap)
            out += encode_varint(r.ack)
        return out

    if isinstance(frame, CryptoFrame):
        out  = encode_varint(FrameType.CRYPTO)
        out += encode_varint(frame.offset)
        out += encode_varint(len(frame.data))
        out += frame.data
        return out

    if isinstance(frame, StreamFrame):
        flags = STREAM_FLAG_LEN
        if frame.offset > 0:
            flags |= STREAM_FLAG_OFF
        if frame.fin:
            flags |= STREAM_FLAG_FIN
        ftype = FrameType.STREAM | flags
        out  = encode_varint(ftype)
        out += encode_varint(frame.stream_id)
        if frame.offset > 0:
            out += encode_varint(frame.offset)
        out += encode_varint(len(frame.data))
        out += frame.data
        return out

    if isinstance(frame, MaxDataFrame):
        return encode_varint(FrameType.MAX_DATA) + encode_varint(frame.maximum)

    if isinstance(frame, MaxStreamDataFrame):
        return (
            encode_varint(FrameType.MAX_STREAM_DATA)
            + encode_varint(frame.stream_id)
            + encode_varint(frame.maximum)
        )

    if isinstance(frame, MaxStreamsFrame):
        ftype = FrameType.MAX_STREAMS_BIDI if frame.bidirectional else FrameType.MAX_STREAMS_UNI
        return encode_varint(ftype) + encode_varint(frame.maximum)

    if isinstance(frame, DataBlockedFrame):
        return encode_varint(FrameType.DATA_BLOCKED) + encode_varint(frame.limit)

    if isinstance(frame, StreamDataBlockedFrame):
        return (
            encode_varint(FrameType.STREAM_DATA_BLOCKED)
            + encode_varint(frame.stream_id)
            + encode_varint(frame.limit)
        )

    if isinstance(frame, ConnectionCloseFrame):
        ftype = FrameType.APPLICATION_CLOSE if frame.application else FrameType.CONNECTION_CLOSE
        out  = encode_varint(ftype)
        out += encode_varint(frame.error_code)
        if not frame.application:
            out += encode_varint(frame.frame_type)
        out += encode_varint(len(frame.reason))
        out += frame.reason
        return out

    if isinstance(frame, HandshakeDoneFrame):
        return encode_varint(FrameType.HANDSHAKE_DONE)

    raise TypeError(f"Unknown frame type: {type(frame)}")


# ── parsing ───────────────────────────────────────────────────────────────────

def decode_frames(payload: bytes) -> list[Frame]:
    """Parse all frames from a packet payload."""
    frames: list[Frame] = []
    off = 0
    while off < len(payload):
        ftype, off = decode_varint(payload, off)

        if ftype == FrameType.PADDING:
            count = 1
            while off < len(payload) and payload[off] == 0x00:
                count += 1
                off   += 1
            frames.append(PaddingFrame(length=count))
            continue

        if ftype == FrameType.PING:
            frames.append(PingFrame())
            continue

        if ftype in (FrameType.ACK, FrameType.ACK_ECN):
            largest, off  = decode_varint(payload, off)
            delay,   off  = decode_varint(payload, off)
            count,   off  = decode_varint(payload, off)
            first,   off  = decode_varint(payload, off)
            ranges = []
            for _ in range(count):
                gap, off = decode_varint(payload, off)
                ack, off = decode_varint(payload, off)
                ranges.append(AckRange(gap=gap, ack=ack))
            if ftype == FrameType.ACK_ECN:
                for _ in range(3):
                    _, off = decode_varint(payload, off)
            frames.append(AckFrame(largest_acked=largest, ack_delay=delay,
                                   first_ack_range=first, ranges=ranges))
            continue

        if ftype == FrameType.CRYPTO:
            offset_v, off = decode_varint(payload, off)
            length,   off = decode_varint(payload, off)
            data = payload[off: off + length]; off += length
            frames.append(CryptoFrame(offset=offset_v, data=data))
            continue

        if (ftype & 0xF8) == FrameType.STREAM:
            flags     = ftype & 0x07
            sid, off  = decode_varint(payload, off)
            offset_v  = 0
            if flags & STREAM_FLAG_OFF:
                offset_v, off = decode_varint(payload, off)
            if flags & STREAM_FLAG_LEN:
                dlen, off = decode_varint(payload, off)
                data = payload[off: off + dlen]; off += dlen
            else:
                data = payload[off:]; off = len(payload)
            fin = bool(flags & STREAM_FLAG_FIN)
            frames.append(StreamFrame(stream_id=sid, offset=offset_v, data=data, fin=fin))
            continue

        if ftype == FrameType.MAX_DATA:
            m, off = decode_varint(payload, off)
            frames.append(MaxDataFrame(maximum=m))
            continue

        if ftype == FrameType.MAX_STREAM_DATA:
            sid, off = decode_varint(payload, off)
            m,   off = decode_varint(payload, off)
            frames.append(MaxStreamDataFrame(stream_id=sid, maximum=m))
            continue

        if ftype in (FrameType.MAX_STREAMS_BIDI, FrameType.MAX_STREAMS_UNI):
            m, off = decode_varint(payload, off)
            frames.append(MaxStreamsFrame(maximum=m, bidirectional=(ftype == FrameType.MAX_STREAMS_BIDI)))
            continue

        if ftype == FrameType.DATA_BLOCKED:
            lim, off = decode_varint(payload, off)
            frames.append(DataBlockedFrame(limit=lim))
            continue

        if ftype == FrameType.STREAM_DATA_BLOCKED:
            sid, off = decode_varint(payload, off)
            lim, off = decode_varint(payload, off)
            frames.append(StreamDataBlockedFrame(stream_id=sid, limit=lim))
            continue

        if ftype in (FrameType.CONNECTION_CLOSE, FrameType.APPLICATION_CLOSE):
            app      = (ftype == FrameType.APPLICATION_CLOSE)
            ec, off  = decode_varint(payload, off)
            ft_val   = 0
            if not app:
                ft_val, off = decode_varint(payload, off)
            rlen, off = decode_varint(payload, off)
            reason    = payload[off: off + rlen]; off += rlen
            frames.append(ConnectionCloseFrame(error_code=ec, frame_type=ft_val,
                                               reason=reason, application=app))
            continue

        if ftype == FrameType.HANDSHAKE_DONE:
            frames.append(HandshakeDoneFrame())
            continue

        # Unknown frame type — stop parsing conservatively
        break

    return frames
