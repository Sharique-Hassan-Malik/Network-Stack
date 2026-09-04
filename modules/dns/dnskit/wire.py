"""DNS message encoding and decoding — RFC 1035 §4, and nothing else.

This module is pure: bytes in, objects out, no sockets and no clock. That is
what lets the parser be fuzzed against hostile input at full speed and what
makes every wire-format decision testable without a network.

The parts that are actually hard are all in name handling, and each has a
matching failure documented at its implementation:

  - **compression pointers can form a loop**, and a parser that follows them
    naively hangs on a packet an attacker can write in four bytes;
  - **a pointer may only point backwards**, or the same loop reappears as
    forward recursion;
  - names are **case-insensitive for comparison but case-preserving on the
    wire**, which is what makes 0x20 encoding possible.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# ---- constants ------------------------------------------------------------

MAX_LABEL = 63          # RFC 1035 §2.3.4
MAX_NAME = 255          # including length bytes and the root's zero
MAX_UDP = 512           # without EDNS0; §4.2.1
POINTER_MASK = 0xC0

# Record types this resolver understands. Others are carried as raw rdata
# rather than rejected: a resolver has to be able to hold an RRset it does not
# interpret, or it cannot follow a delegation that includes one.
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_OPT = 41

CLASS_IN = 1

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_PTR: "PTR", TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
    TYPE_OPT: "OPT",
}
NAME_TYPES = {v: k for k, v in TYPE_NAMES.items()}

# RCODEs worth naming; §4.1.1.
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


class WireError(ValueError):
    """A malformed message. Carries what was wrong and where.

    A parse failure is an ordinary outcome for a resolver — one broken reply
    among thousands must not stop the others — so it is an exception with an
    offset rather than an assertion.
    """

    def __init__(self, message: str, offset: int | None = None) -> None:
        self.offset = offset
        super().__init__(message if offset is None else f"{message} (at offset {offset})")


# ---- names ----------------------------------------------------------------

def normalise(name: str) -> str:
    """Lower-case, with exactly one trailing dot.

    Comparison is case-insensitive (RFC 4343), so every name that will be
    compared or used as a cache key passes through here. The wire form keeps
    whatever case it arrived with, which is what allows 0x20 encoding.
    """
    if not name or name == ".":
        return "."
    return name.rstrip(".").lower() + "."


def encode_name(name: str) -> bytes:
    """Encode a name as length-prefixed labels ending in a zero byte.

    No compression is emitted. A query contains one name, so a pointer could
    only ever point at the header — compression saves nothing here and costs a
    class of bug.
    """
    if name in ("", "."):
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not raw:
            raise WireError("empty label in name")
        if len(raw) > MAX_LABEL:
            raise WireError(f"label longer than {MAX_LABEL} bytes: {label!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_NAME:
        raise WireError(f"name longer than {MAX_NAME} bytes")
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a name, following compression pointers.

    Returns the name and the offset just past the name *in the original
    position* — following a pointer must not advance the caller's cursor past
    the two pointer bytes, which is the whole point of compression.

    Two bounds are enforced, and neither is optional:

      - a pointer must point strictly backwards. Forward or self-referential
        pointers are how a four-byte packet makes a naive parser loop forever.
      - the total decoded length is capped at MAX_NAME. A chain of legal
        backward pointers can still describe a name of unbounded length, so
        the pointer rule alone does not bound the work.
    """
    labels: list[str] = []
    jumped = False
    end_offset = offset
    total = 0
    seen: set[int] = set()

    while True:
        if offset >= len(data):
            raise WireError("name runs past the end of the message", offset)
        length = data[offset]

        if length & POINTER_MASK == POINTER_MASK:
            if offset + 1 >= len(data):
                raise WireError("truncated compression pointer", offset)
            target = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
                jumped = True
            if target >= offset:
                raise WireError("compression pointer does not point backwards", offset)
            if target in seen:
                raise WireError("compression pointer loop", offset)
            seen.add(target)
            offset = target
            continue

        if length & POINTER_MASK:
            raise WireError(f"reserved label type {length:#04x}", offset)

        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break

        offset += 1
        if offset + length > len(data):
            raise WireError("label runs past the end of the message", offset)
        total += length + 1
        if total > MAX_NAME:
            raise WireError("decoded name exceeds the maximum length", offset)
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length

    return (".".join(labels) + "." if labels else "."), end_offset


# ---- records --------------------------------------------------------------

@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN

    def __str__(self) -> str:
        return f"{self.name} {TYPE_NAMES.get(self.qtype, self.qtype)}"


@dataclass(frozen=True)
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    # Parsed form for the types the resolver acts on. Names inside rdata must
    # be decompressed against the whole message, so they cannot be recovered
    # from `rdata` alone once the message is gone — which is why they are
    # resolved at parse time rather than lazily.
    parsed: object = None

    def __str__(self) -> str:
        kind = TYPE_NAMES.get(self.rtype, str(self.rtype))
        return f"{self.name} {self.ttl} {kind} {self.value}"

    @property
    def value(self) -> str:
        if self.parsed is not None:
            return str(self.parsed)
        return self.rdata.hex()


@dataclass
class Message:
    ident: int = 0
    response: bool = False
    opcode: int = 0
    authoritative: bool = False
    truncated: bool = False
    recursion_desired: bool = False
    recursion_available: bool = False
    rcode: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, str(self.rcode))


def _parse_rdata(rtype: int, data: bytes, start: int, length: int):
    """Interpret rdata for the types the resolver acts on."""
    end = start + length
    if rtype == TYPE_A and length == 4:
        return ".".join(str(b) for b in data[start:end])
    if rtype == TYPE_AAAA and length == 16:
        parts = [f"{data[start + i]:02x}{data[start + i + 1]:02x}" for i in range(0, 16, 2)]
        return ":".join(parts)
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        name, _ = decode_name(data, start)
        return name
    if rtype == TYPE_MX and length >= 3:
        pref = struct.unpack_from("!H", data, start)[0]
        name, _ = decode_name(data, start + 2)
        return f"{pref} {name}"
    if rtype == TYPE_TXT:
        out, i = [], start
        while i < end:
            n = data[i]
            out.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        return " ".join(out)
    if rtype == TYPE_SOA:
        mname, off = decode_name(data, start)
        rname, off = decode_name(data, off)
        if off + 20 <= end:
            serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, off)
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        return f"{mname} {rname}"
    return None


def encode_query(name: str, qtype: int, ident: int, *,
                 recursion_desired: bool = False) -> bytes:
    """A single-question query. `ident` is the caller's to choose.

    The identifier is not generated here on purpose: it is the only thing
    protecting against off-path spoofing, so it must come from a source the
    caller controls and can make unpredictable, not from a default this module
    picks.
    """
    flags = 0x0100 if recursion_desired else 0x0000
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def decode_message(data: bytes) -> Message:
    """Parse a complete DNS message. Raises WireError on anything malformed."""
    if len(data) < 12:
        raise WireError("message shorter than a header")

    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    msg = Message(
        ident=ident,
        response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        recursion_desired=bool(flags & 0x0100),
        recursion_available=bool(flags & 0x0080),
        rcode=flags & 0x000F,
    )

    offset = 12
    for _ in range(qd):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise WireError("question truncated", offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        msg.questions.append(Question(name, qtype, qclass))

    def read_records(count: int, into: list[Record], off: int) -> int:
        for _ in range(count):
            name, off = decode_name(data, off)
            if off + 10 > len(data):
                raise WireError("record header truncated", off)
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if off + rdlen > len(data):
                raise WireError("rdata runs past the end of the message", off)
            parsed = None
            try:
                parsed = _parse_rdata(rtype, data, off, rdlen)
            except WireError:
                # An unparseable rdata for a type we merely pass through is not
                # fatal to the message. Losing the whole reply because one
                # additional record is malformed would be a denial of service
                # any authoritative server could trigger by accident.
                parsed = None
            into.append(Record(name, rtype, rclass, ttl, data[off:off + rdlen], parsed))
            off += rdlen
        return off

    offset = read_records(an, msg.answers, offset)
    offset = read_records(ns, msg.authority, offset)
    offset = read_records(ar, msg.additional, offset)
    return msg
