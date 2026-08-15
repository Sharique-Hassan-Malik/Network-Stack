"""
Auto-detect MRT binary format vs bgpdump text format by sniffing the
first record header and checking that the MRT type code is one of the
known TABLE_DUMP_V2 or BGP4MP values.
"""

from __future__ import annotations

import bz2
import gzip
import struct
from pathlib import Path
from typing import Iterator

from bgp_analyzer.core.types import Route
from bgp_analyzer.parsers.mrt import MRTParser
from bgp_analyzer.parsers.bgpdump import parse_bgpdump

_KNOWN_MRT_TYPES = {13, 16, 17}


def _is_mrt(path: Path) -> bool:
    try:
        suffix = path.suffix.lower()
        if suffix == ".gz":
            fh = gzip.open(path, "rb")
        elif suffix in (".bz2", ".bz"):
            fh = bz2.open(path, "rb")
        else:
            fh = open(path, "rb")
        with fh:
            header = fh.read(12)
            if len(header) < 6:
                return False
            mrt_type = struct.unpack_from("!H", header, 4)[0]
            return mrt_type in _KNOWN_MRT_TYPES
    except Exception:
        return False


def load_routes(path: str | Path) -> Iterator[Route]:
    """Stream Route objects from an MRT binary file or a bgpdump text file."""
    p = Path(path)
    if _is_mrt(p):
        yield from MRTParser(p).routes()
    else:
        yield from parse_bgpdump(p)
