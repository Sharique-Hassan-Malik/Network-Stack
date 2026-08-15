"""
Parser for bgpdump -m output (pipe-delimited one-route-per-line format).

Supported line format:
  TABLE_DUMP2|epoch|B|peer_ip|peer_as|prefix|aspath|origin[|nexthop[|...]]
  BGP4MP|epoch|A|peer_ip|peer_as|prefix|aspath|origin[|nexthop]
  BGP4MP|epoch|W|...  (withdrawal — skipped)

The origin field is IGP/EGP/INCOMPLETE and is not stored on Route.
AS sets in the path are written as {ASN ASN ...}.
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
from pathlib import Path
from typing import Iterator, Optional, TextIO

from bgp_analyzer.core.types import (
    AS_SEQUENCE,
    AS_SET,
    ASPath,
    ASPathSegment,
    Route,
)


def parse_bgpdump(path: str | Path) -> Iterator[Route]:
    """Yield Route objects from a bgpdump -m text file."""
    with _open(Path(path)) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            route = _parse_line(line)
            if route is not None:
                yield route


def _open(path: Path) -> TextIO:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    if suffix in (".bz2", ".bz"):
        return bz2.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def _parse_line(line: str) -> Optional[Route]:
    parts = line.split("|")
    if len(parts) < 7:
        return None

    record_type = parts[0]
    if record_type not in ("TABLE_DUMP2", "BGP4MP"):
        return None

    try:
        ts = int(parts[1])
    except ValueError:
        return None

    if parts[2] == "W":
        return None  # withdrawal

    peer_ip = parts[3] if len(parts) > 3 else None

    try:
        peer_as: Optional[int] = int(parts[4])
    except (ValueError, IndexError):
        peer_as = None

    try:
        prefix = ipaddress.ip_network(parts[5], strict=False)
    except (ValueError, IndexError):
        return None

    as_path = _parse_path_str(parts[6]) if len(parts) > 6 and parts[6] else None
    next_hop = parts[8] if len(parts) > 8 and parts[8] else None

    return Route(
        prefix=prefix,
        origin_as=as_path.origin if as_path else None,
        as_path=as_path,
        peer_as=peer_as,
        peer_ip=peer_ip,
        timestamp=ts,
        next_hop=next_hop,
    )


def _parse_path_str(s: str) -> Optional[ASPath]:
    """
    Parse a space-delimited AS path string.

    Examples:
      "3333 13335"
      "3333 {64496 64497} 13335"
    """
    s = s.strip()
    if not s:
        return None

    segments: list[ASPathSegment] = []
    seq_buf: list[int] = []
    i = 0
    tokens = s.split()

    while i < len(tokens):
        tok = tokens[i]

        if tok.startswith("{"):
            if seq_buf:
                segments.append(ASPathSegment(kind=AS_SEQUENCE, asns=tuple(seq_buf)))
                seq_buf = []
            # Collect tokens until the closing brace
            combined = tok
            while i < len(tokens) and "}" not in combined:
                i += 1
                combined += " " + tokens[i]
            clean = combined.replace("{", "").replace("}", "")
            set_asns: list[int] = []
            for part in clean.split():
                try:
                    set_asns.append(int(part))
                except ValueError:
                    pass
            if set_asns:
                segments.append(ASPathSegment(kind=AS_SET, asns=tuple(set_asns)))
        else:
            try:
                seq_buf.append(int(tok))
            except ValueError:
                pass
        i += 1

    if seq_buf:
        segments.append(ASPathSegment(kind=AS_SEQUENCE, asns=tuple(seq_buf)))

    if not segments:
        return None
    return ASPath(segments=tuple(segments))
