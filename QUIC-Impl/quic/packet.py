"""
QUIC packet header layout (RFC 9000 §17).

Long header (Initial / Handshake / 0-RTT)
─────────────────────────────────────────
  1 byte  first_byte  : 1|1|type(2)|reserved(2)|pn_len(2)
  4 bytes version     : 0x00000001 (QUIC v1)
  1 byte  dcid_len
  N bytes dcid        (destination connection ID)
  1 byte  scid_len
  M bytes scid        (source connection ID)
  varint  token_len   (Initial only; 0 otherwise)
  [token]
  varint  length      (number of bytes from pn through end of payload)
  1-4b    packet_number (pn_len+1 bytes, truncated)
  payload

Short header (1-RTT)
─────────────────────
  1 byte  first_byte  : 0|1|spin(1)|reserved(2)|key_phase(1)|pn_len(2)
  N bytes dcid
  1-4b    packet_number
  payload

This implementation omits TLS 1.3 encryption (AEAD) since it focuses on
transport mechanics.  The "encryption" layer is a trivial XOR cipher keyed
on the connection ID used purely to demonstrate where the crypto layer sits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .types import PacketType, encode_varint, decode_varint

QUIC_VERSION = 0x00000001


@dataclass
class LongHeader:
    ptype:    PacketType
    version:  int   = QUIC_VERSION
    dcid:     bytes = b""
    scid:     bytes = b""
    token:    bytes = b""      # Initial packets only
    pn:       int   = 0
    pn_len:   int   = 2        # 1-4 bytes

    def to_bytes(self, payload: bytes) -> bytes:
        pn_len_field = self.pn_len - 1   # stored as 0-3
        first = (
            0xC0                          # long header marker (bits 7-6)
            | ((self.ptype & 0x03) << 4)  # packet type in bits 5-4
            | pn_len_field                # pn length in bits 1-0
        )
        pn_bytes = self.pn.to_bytes(self.pn_len, "big")
        token_enc = (encode_varint(len(self.token)) + self.token
                     if self.ptype == PacketType.INITIAL else b"")
        length_val = self.pn_len + len(payload)

        return (
            struct.pack("!B", first)
            + struct.pack("!I", self.version)
            + struct.pack("!B", len(self.dcid)) + self.dcid
            + struct.pack("!B", len(self.scid)) + self.scid
            + token_enc
            + encode_varint(length_val)
            + pn_bytes
            + payload
        )

    @classmethod
    def from_bytes(cls, buf: bytes) -> tuple["LongHeader", bytes, int]:
        """
        Parse a long-header packet.
        Returns (header, payload, total_bytes_consumed).
        """
        if not buf:
            raise ValueError("Empty buffer")
        first = buf[0]
        if not (first & 0x80):
            raise ValueError("Not a long header packet")

        ptype   = PacketType((first >> 4) & 0x03)
        pn_len  = (first & 0x03) + 1
        version = struct.unpack_from("!I", buf, 1)[0]
        off     = 5

        dcid_len = buf[off]; off += 1
        dcid     = buf[off: off + dcid_len]; off += dcid_len

        scid_len = buf[off]; off += 1
        scid     = buf[off: off + scid_len]; off += scid_len

        token = b""
        if ptype == PacketType.INITIAL:
            token_len, off = decode_varint(buf, off)
            token = buf[off: off + token_len]; off += token_len

        length, off = decode_varint(buf, off)
        pn = int.from_bytes(buf[off: off + pn_len], "big")
        off += pn_len

        payload_len = length - pn_len
        payload     = buf[off: off + payload_len]

        hdr = cls(ptype=ptype, version=version, dcid=dcid, scid=scid,
                  token=token, pn=pn, pn_len=pn_len)
        return hdr, payload, off + payload_len


@dataclass
class ShortHeader:
    dcid:   bytes = b""
    pn:     int   = 0
    pn_len: int   = 2
    spin:   bool  = False

    def to_bytes(self, payload: bytes) -> bytes:
        pn_len_field = self.pn_len - 1
        first = 0x40 | (int(self.spin) << 5) | pn_len_field
        return (
            struct.pack("!B", first)
            + self.dcid
            + self.pn.to_bytes(self.pn_len, "big")
            + payload
        )

    @classmethod
    def from_bytes(cls, buf: bytes, dcid_len: int = 8) -> tuple["ShortHeader", bytes, int]:
        first  = buf[0]
        spin   = bool(first & 0x20)
        pn_len = (first & 0x03) + 1
        off    = 1
        dcid   = buf[off: off + dcid_len]; off += dcid_len
        pn     = int.from_bytes(buf[off: off + pn_len], "big"); off += pn_len
        return cls(dcid=dcid, pn=pn, pn_len=pn_len, spin=spin), buf[off:], off
