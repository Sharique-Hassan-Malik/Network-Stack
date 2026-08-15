"""
MRT format parser per RFC 6396.

Supported record types:
  TABLE_DUMP_V2 (13)
    PEER_INDEX_TABLE (1)
    RIB_IPV4_UNICAST (2)  RIB_IPV4_MULTICAST (3)
    RIB_IPV6_UNICAST (4)  RIB_IPV6_MULTICAST (5)
  BGP4MP (16) and BGP4MP_ET (17)
    BGP4MP_MESSAGE (1)  BGP4MP_MESSAGE_AS4 (4)
    BGP4MP_STATE_CHANGE (0)  BGP4MP_STATE_CHANGE_AS4 (5)

The parser streams Route objects without loading the entire file into
memory, making it suitable for RIPE NCC dumps which often exceed 1 GB
uncompressed.
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import struct
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from bgp_analyzer.core.types import (
    AS_SEQUENCE,
    AS_SET,
    ASPath,
    ASPathSegment,
    Route,
)

# MRT type codes
TABLE_DUMP_V2 = 13
BGP4MP        = 16
BGP4MP_ET     = 17

# TABLE_DUMP_V2 subtypes
TD2_PEER_INDEX      = 1
TD2_RIB_IPV4_UNI    = 2
TD2_RIB_IPV4_MULTI  = 3
TD2_RIB_IPV6_UNI    = 4
TD2_RIB_IPV6_MULTI  = 5

# BGP4MP subtypes
BGP4MP_STATE_CHANGE     = 0
BGP4MP_MESSAGE          = 1
BGP4MP_MESSAGE_AS4      = 4
BGP4MP_STATE_CHANGE_AS4 = 5

# BGP message types
BGP_UPDATE = 2

# BGP path attribute type codes
ATTR_ORIGIN      = 1
ATTR_AS_PATH     = 2
ATTR_NEXT_HOP    = 3
ATTR_MED         = 4
ATTR_LOCAL_PREF  = 5
ATTR_COMMUNITIES = 8
ATTR_AS4_PATH    = 17

_HDR = struct.Struct("!IHHI")  # timestamp, type, subtype, length — 12 bytes


class MRTParser:

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._peers: list[dict] = []

    def routes(self) -> Iterator[Route]:
        with self._open() as fh:
            yield from self._parse(fh)

    def _open(self) -> BinaryIO:
        suffix = self._path.suffix.lower()
        if suffix == ".gz":
            return gzip.open(self._path, "rb")
        if suffix in (".bz2", ".bz"):
            return bz2.open(self._path, "rb")
        return open(self._path, "rb")

    def _parse(self, fh: BinaryIO) -> Iterator[Route]:
        while True:
            raw = fh.read(12)
            if len(raw) < 12:
                break

            ts, mrt_type, subtype, length = _HDR.unpack(raw)
            data = fh.read(length)
            if len(data) < length:
                break

            try:
                if mrt_type == TABLE_DUMP_V2:
                    yield from self._handle_td2(ts, subtype, data)
                elif mrt_type in (BGP4MP, BGP4MP_ET):
                    et_offset = 4 if mrt_type == BGP4MP_ET else 0
                    yield from self._handle_bgp4mp(ts, subtype, data[et_offset:])
            except (struct.error, IndexError, ValueError):
                continue

    # ------------------------------------------------------------------ TD2

    def _handle_td2(self, ts: int, subtype: int, data: bytes) -> Iterator[Route]:
        if subtype == TD2_PEER_INDEX:
            self._peers = list(_parse_peer_index(data))
        elif subtype in (TD2_RIB_IPV4_UNI, TD2_RIB_IPV4_MULTI):
            yield from _parse_rib(data, ts, self._peers, ipv6=False)
        elif subtype in (TD2_RIB_IPV6_UNI, TD2_RIB_IPV6_MULTI):
            yield from _parse_rib(data, ts, self._peers, ipv6=True)

    # ---------------------------------------------------------------- BGP4MP

    def _handle_bgp4mp(self, ts: int, subtype: int, data: bytes) -> Iterator[Route]:
        if subtype in (BGP4MP_STATE_CHANGE, BGP4MP_STATE_CHANGE_AS4):
            return

        pos = 0
        as4 = subtype == BGP4MP_MESSAGE_AS4

        if as4:
            peer_as  = struct.unpack_from("!I", data, pos)[0]; pos += 4
            _loc_as  = struct.unpack_from("!I", data, pos)[0]; pos += 4
        else:
            peer_as  = struct.unpack_from("!H", data, pos)[0]; pos += 2
            _loc_as  = struct.unpack_from("!H", data, pos)[0]; pos += 2

        afi = struct.unpack_from("!H", data, pos)[0]; pos += 2
        pos += 2  # interface index

        if afi == 1:
            peer_ip = str(ipaddress.IPv4Address(data[pos:pos + 4])); pos += 4
            pos += 4   # local IP
            ipv6 = False
        else:
            peer_ip = str(ipaddress.IPv6Address(data[pos:pos + 16])); pos += 16
            pos += 16
            ipv6 = True

        # BGP common header: 16-byte marker + 2-byte length + 1-byte type
        pos += 16
        bgp_len  = struct.unpack_from("!H", data, pos)[0]; pos += 2
        bgp_type = data[pos]; pos += 1

        if bgp_type != BGP_UPDATE:
            return

        yield from _parse_bgp_update(
            data[pos:pos + bgp_len - 19],
            ts=ts,
            peer_as=peer_as,
            peer_ip=peer_ip,
            ipv6=ipv6,
            as4=as4,
        )


# ----------------------------------------------------------------- helpers


def _parse_peer_index(data: bytes) -> Iterator[dict]:
    pos = 4  # skip collector BGP ID
    vname_len = struct.unpack_from("!H", data, pos)[0]; pos += 2 + vname_len
    peer_count = struct.unpack_from("!H", data, pos)[0]; pos += 2

    for _ in range(peer_count):
        peer_type = data[pos]; pos += 1
        as4  = bool(peer_type & 0x02)
        ipv6 = bool(peer_type & 0x01)

        pos += 4  # BGP ID

        if ipv6:
            peer_ip = str(ipaddress.IPv6Address(data[pos:pos + 16])); pos += 16
        else:
            peer_ip = str(ipaddress.IPv4Address(data[pos:pos + 4])); pos += 4

        if as4:
            peer_as = struct.unpack_from("!I", data, pos)[0]; pos += 4
        else:
            peer_as = struct.unpack_from("!H", data, pos)[0]; pos += 2

        yield {"ip": peer_ip, "as": peer_as}


def _parse_rib(
    data: bytes, ts: int, peers: list[dict], ipv6: bool
) -> Iterator[Route]:
    pos = 4  # skip sequence number
    prefix_len = data[pos]; pos += 1
    nbytes = (prefix_len + 7) // 8
    raw_prefix = data[pos:pos + nbytes]; pos += nbytes

    if ipv6:
        addr = ipaddress.IPv6Address(raw_prefix.ljust(16, b"\x00"))
        prefix = ipaddress.IPv6Network(f"{addr}/{prefix_len}", strict=False)
    else:
        addr = ipaddress.IPv4Address(raw_prefix.ljust(4, b"\x00"))
        prefix = ipaddress.IPv4Network(f"{addr}/{prefix_len}", strict=False)

    entry_count = struct.unpack_from("!H", data, pos)[0]; pos += 2

    for _ in range(entry_count):
        if pos + 8 > len(data):
            break
        peer_idx   = struct.unpack_from("!H", data, pos)[0]
        orig_time  = struct.unpack_from("!I", data, pos + 2)[0]
        attr_len   = struct.unpack_from("!H", data, pos + 6)[0]
        pos += 8

        attr_data = data[pos:pos + attr_len]; pos += attr_len
        peer = peers[peer_idx] if peer_idx < len(peers) else {}
        attrs = _parse_attributes(attr_data, as4=True)

        as_path = attrs.get("as_path")
        if attrs.get("as4_path"):
            as_path = attrs["as4_path"]

        yield Route(
            prefix=prefix,
            origin_as=as_path.origin if as_path else None,
            as_path=as_path,
            peer_as=peer.get("as"),
            peer_ip=peer.get("ip"),
            timestamp=orig_time or ts,
            next_hop=attrs.get("next_hop"),
            local_pref=attrs.get("local_pref"),
            med=attrs.get("med"),
            communities=tuple(attrs.get("communities", [])),
        )


def _parse_bgp_update(
    data: bytes,
    ts: int,
    peer_as: int,
    peer_ip: str,
    ipv6: bool,
    as4: bool,
) -> Iterator[Route]:
    pos = 0

    withdrawn_len = struct.unpack_from("!H", data, pos)[0]; pos += 2
    pos += withdrawn_len

    if pos + 2 > len(data):
        return
    attr_len  = struct.unpack_from("!H", data, pos)[0]; pos += 2
    attr_data = data[pos:pos + attr_len]; pos += attr_len

    attrs   = _parse_attributes(attr_data, as4=as4)
    as_path = attrs.get("as_path")
    if attrs.get("as4_path"):
        as_path = attrs["as4_path"]
    origin_as = as_path.origin if as_path else None

    while pos < len(data):
        prefix_len = data[pos]; pos += 1
        nbytes     = (prefix_len + 7) // 8
        raw        = data[pos:pos + nbytes]; pos += nbytes

        try:
            if ipv6:
                addr   = ipaddress.IPv6Address(raw.ljust(16, b"\x00"))
                prefix = ipaddress.IPv6Network(f"{addr}/{prefix_len}", strict=False)
            else:
                addr   = ipaddress.IPv4Address(raw.ljust(4, b"\x00"))
                prefix = ipaddress.IPv4Network(f"{addr}/{prefix_len}", strict=False)
        except ValueError:
            continue

        yield Route(
            prefix=prefix,
            origin_as=origin_as,
            as_path=as_path,
            peer_as=peer_as,
            peer_ip=peer_ip,
            timestamp=ts,
            next_hop=attrs.get("next_hop"),
            communities=tuple(attrs.get("communities", [])),
        )


def _parse_attributes(data: bytes, as4: bool) -> dict:
    attrs: dict = {}
    pos = 0

    while pos < len(data):
        if pos + 2 > len(data):
            break
        flags     = data[pos]; pos += 1
        type_code = data[pos]; pos += 1
        extended  = bool(flags & 0x10)

        if extended:
            if pos + 2 > len(data):
                break
            length = struct.unpack_from("!H", data, pos)[0]; pos += 2
        else:
            if pos >= len(data):
                break
            length = data[pos]; pos += 1

        if pos + length > len(data):
            break
        value = data[pos:pos + length]; pos += length

        if type_code == ATTR_AS_PATH:
            attrs["as_path"] = _parse_as_path(value, as4=as4)
        elif type_code == ATTR_AS4_PATH:
            attrs["as4_path"] = _parse_as_path(value, as4=True)
        elif type_code == ATTR_NEXT_HOP and len(value) >= 4:
            attrs["next_hop"] = str(ipaddress.IPv4Address(value[:4]))
        elif type_code == ATTR_LOCAL_PREF and len(value) >= 4:
            attrs["local_pref"] = struct.unpack("!I", value[:4])[0]
        elif type_code == ATTR_MED and len(value) >= 4:
            attrs["med"] = struct.unpack("!I", value[:4])[0]
        elif type_code == ATTR_COMMUNITIES:
            comms: list[str] = []
            for i in range(0, len(value) - 3, 4):
                hi = struct.unpack_from("!H", value, i)[0]
                lo = struct.unpack_from("!H", value, i + 2)[0]
                comms.append(f"{hi}:{lo}")
            attrs["communities"] = comms

    return attrs


def _parse_as_path(data: bytes, as4: bool) -> Optional[ASPath]:
    segments: list[ASPathSegment] = []
    pos      = 0
    as_size  = 4 if as4 else 2
    fmt      = "!I" if as4 else "!H"

    while pos < len(data):
        if pos + 2 > len(data):
            break
        seg_type = data[pos]; pos += 1
        seg_len  = data[pos]; pos += 1

        asns: list[int] = []
        for _ in range(seg_len):
            if pos + as_size > len(data):
                break
            asns.append(struct.unpack_from(fmt, data, pos)[0])
            pos += as_size

        segments.append(ASPathSegment(kind=seg_type, asns=tuple(asns)))

    if not segments:
        return None
    return ASPath(segments=tuple(segments))
