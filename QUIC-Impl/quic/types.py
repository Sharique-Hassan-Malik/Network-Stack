"""
QUIC primitive types and variable-length integer codec (RFC 9000 §16).

Variable-length integers encode values 0–2^62−1 in 1, 2, 4 or 8 bytes.
The two most-significant bits of the first byte encode the length:

  00  → 1 byte   (values 0–63)
  01  → 2 bytes  (values 0–16383)
  10  → 4 bytes  (values 0–1073741823)
  11  → 8 bytes  (values 0–4611686018427387903)
"""

import struct
from enum import IntEnum


# ── packet type codes ─────────────────────────────────────────────────────────

class PacketType(IntEnum):
    INITIAL     = 0x00
    ZERO_RTT    = 0x01
    HANDSHAKE   = 0x02
    RETRY       = 0x03
    ONE_RTT     = 0x40   # short header; high bit of first byte is 0


# ── frame type codes (RFC 9000 §19) ──────────────────────────────────────────

class FrameType(IntEnum):
    PADDING             = 0x00
    PING                = 0x01
    ACK                 = 0x02
    ACK_ECN             = 0x03
    RESET_STREAM        = 0x04
    STOP_SENDING        = 0x05
    CRYPTO              = 0x06
    NEW_TOKEN           = 0x07
    STREAM              = 0x08   # base; bits 0-2 encode OFF/LEN/FIN
    MAX_DATA            = 0x10
    MAX_STREAM_DATA     = 0x11
    MAX_STREAMS_BIDI    = 0x12
    MAX_STREAMS_UNI     = 0x13
    DATA_BLOCKED        = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED_BIDI= 0x16
    STREAMS_BLOCKED_UNI = 0x17
    NEW_CONNECTION_ID   = 0x18
    RETIRE_CONNECTION_ID= 0x19
    PATH_CHALLENGE      = 0x1a
    PATH_RESPONSE       = 0x1b
    CONNECTION_CLOSE    = 0x1c
    APPLICATION_CLOSE   = 0x1d
    HANDSHAKE_DONE      = 0x1e


STREAM_FLAG_FIN = 0x01
STREAM_FLAG_LEN = 0x02
STREAM_FLAG_OFF = 0x04


# ── variable-length integer ───────────────────────────────────────────────────

def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"Negative varint: {value}")
    if value <= 0x3F:
        return struct.pack("B", value)
    if value <= 0x3FFF:
        return struct.pack("!H", 0x4000 | value)
    if value <= 0x3FFF_FFFF:
        return struct.pack("!I", 0x8000_0000 | value)
    if value <= 0x3FFF_FFFF_FFFF_FFFF:
        return struct.pack("!Q", 0xC000_0000_0000_0000 | value)
    raise ValueError(f"Varint out of range: {value}")


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a variable-length integer from buf starting at offset.

    Returns (value, new_offset).
    """
    if offset >= len(buf):
        raise ValueError("Buffer too short for varint")
    prefix = buf[offset] >> 6
    if prefix == 0:
        return buf[offset] & 0x3F, offset + 1
    if prefix == 1:
        if offset + 2 > len(buf):
            raise ValueError("Buffer too short for 2-byte varint")
        v = struct.unpack_from("!H", buf, offset)[0] & 0x3FFF
        return v, offset + 2
    if prefix == 2:
        if offset + 4 > len(buf):
            raise ValueError("Buffer too short for 4-byte varint")
        v = struct.unpack_from("!I", buf, offset)[0] & 0x3FFF_FFFF
        return v, offset + 4
    # prefix == 3
    if offset + 8 > len(buf):
        raise ValueError("Buffer too short for 8-byte varint")
    v = struct.unpack_from("!Q", buf, offset)[0] & 0x3FFF_FFFF_FFFF_FFFF
    return v, offset + 8


def varint_len(value: int) -> int:
    """Number of bytes needed to encode value as a QUIC varint."""
    if value <= 0x3F:           return 1
    if value <= 0x3FFF:         return 2
    if value <= 0x3FFF_FFFF:   return 4
    return 8


# ── connection ID ─────────────────────────────────────────────────────────────

import os

def new_connection_id(length: int = 8) -> bytes:
    return os.urandom(length)
