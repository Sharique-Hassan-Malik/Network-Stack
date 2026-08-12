"""
Packet layout (26 bytes, big-endian network order):

  seq_num   : uint32    offset  0  — byte-offset sequence number
  ack_num   : uint32    offset  4  — cumulative acknowledgement
  flags     : uint8     offset  8  — SYN / ACK / FIN / RST / DATA
  reserved  : uint8     offset  9
  window    : uint16    offset 10  — advertised receive window
  checksum  : uint16    offset 12  — CRC-32 lower 16 bits
  data_len  : uint32    offset 14  — payload length in bytes
  timestamp : uint64    offset 18  — monotonic microseconds (for RTT)
  [payload  : data_len bytes]
"""

import struct
import zlib
from dataclasses import dataclass, field

F_SYN  = 0x01
F_ACK  = 0x02
F_FIN  = 0x04
F_RST  = 0x08
F_DATA = 0x10

_FMT  = "!IIBBHHIQ"
HEADER_SIZE     = struct.calcsize(_FMT)   # 26 bytes
MAX_SEGMENT_DATA = 1400
SEQ_SPACE       = 2 ** 32

assert HEADER_SIZE == 26


@dataclass
class Packet:
    seq:       int   = 0
    ack:       int   = 0
    flags:     int   = 0
    window:    int   = 65535
    data:      bytes = field(default_factory=bytes)
    timestamp: int   = 0

    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)

    def to_bytes(self) -> bytes:
        payload = self.data or b""
        header = struct.pack(
            _FMT,
            self.seq, self.ack,
            self.flags, 0,
            self.window, 0,
            len(payload), self.timestamp,
        )
        csum = zlib.crc32(header + payload) & 0xFFFF
        header = header[:12] + struct.pack("!H", csum) + header[14:]
        return header + payload

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Packet":
        if len(raw) < HEADER_SIZE:
            raise ValueError(f"Too short: {len(raw)} bytes")
        seq, ack, flags, _, window, checksum, data_len, ts = struct.unpack(
            _FMT, raw[:HEADER_SIZE]
        )
        payload = raw[HEADER_SIZE: HEADER_SIZE + data_len]
        if len(payload) < data_len:
            raise ValueError("Truncated payload")
        zeroed = raw[:12] + b"\x00\x00" + raw[14: HEADER_SIZE + data_len]
        expected = zlib.crc32(zeroed) & 0xFFFF
        if expected != checksum:
            raise ValueError(f"Checksum mismatch: got {checksum:#06x}, expected {expected:#06x}")
        return cls(seq=seq, ack=ack, flags=flags, window=window,
                   data=payload, timestamp=ts)

    def __repr__(self) -> str:
        names = [("S", F_SYN), ("A", F_ACK), ("F", F_FIN), ("R", F_RST), ("D", F_DATA)]
        f = "".join(c for c, v in names if self.flags & v)
        return f"Packet(seq={self.seq}, ack={self.ack}, flags={f!r}, len={len(self.data)})"
