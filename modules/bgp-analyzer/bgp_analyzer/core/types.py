"""
Core data types for BGP route analysis.

Route          — one RIB entry or UPDATE announcement
ASPath         — parsed AS path (segments of sequences and sets)
ASPathSegment  — one AS_SEQUENCE or AS_SET segment
Alert          — one detected anomaly
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from typing import Union, Optional

IPNetwork = Union[IPv4Network, IPv6Network]

AS_SET      = 1
AS_SEQUENCE = 2


@dataclass(frozen=True, slots=True)
class ASPathSegment:
    kind: int
    asns: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ASPath:
    segments: tuple[ASPathSegment, ...]

    @property
    def origin(self) -> Optional[int]:
        """Last ASN in the final AS_SEQUENCE segment."""
        for seg in reversed(self.segments):
            if seg.kind == AS_SEQUENCE and seg.asns:
                return seg.asns[-1]
        return None

    @property
    def all_asns(self) -> list[int]:
        result: list[int] = []
        for seg in self.segments:
            result.extend(seg.asns)
        return result

    @property
    def length(self) -> int:
        return sum(len(seg.asns) for seg in self.segments)

    def has_loop(self) -> bool:
        seen: set[int] = set()
        for asn in self.all_asns:
            if asn in seen:
                return True
            seen.add(asn)
        return False

    def __str__(self) -> str:
        parts: list[str] = []
        for seg in self.segments:
            if seg.kind == AS_SET:
                parts.append("{" + " ".join(str(a) for a in seg.asns) + "}")
            else:
                parts.extend(str(a) for a in seg.asns)
        return " ".join(parts)


@dataclass(frozen=True, slots=True)
class Route:
    prefix: IPNetwork
    origin_as: Optional[int]
    as_path: Optional[ASPath]
    peer_as: Optional[int]
    peer_ip: Optional[str]
    timestamp: int
    next_hop: Optional[str] = None
    local_pref: Optional[int] = None
    med: Optional[int] = None
    communities: tuple[str, ...] = field(default_factory=tuple)

    @property
    def path_str(self) -> str:
        return str(self.as_path) if self.as_path else ""

    @property
    def origin_str(self) -> str:
        return str(self.origin_as) if self.origin_as is not None else "unknown"


@dataclass
class Alert:
    kind: str
    severity: str
    prefix: IPNetwork
    description: str
    current_route: Optional[Route] = None
    baseline_routes: list[Route] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "kind": self.kind,
            "severity": self.severity,
            "prefix": str(self.prefix),
            "description": self.description,
            "extra": self.extra,
        }
        if self.current_route:
            r = self.current_route
            d["current"] = {
                "origin_as": r.origin_as,
                "as_path": r.path_str,
                "peer_as": r.peer_as,
                "peer_ip": r.peer_ip,
                "timestamp": r.timestamp,
            }
        if self.baseline_routes:
            d["baseline"] = [
                {"origin_as": r.origin_as, "as_path": r.path_str}
                for r in self.baseline_routes[:5]
            ]
        return d
