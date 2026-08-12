"""
Passive OS fingerprinting from observed packet fields.

This implementation uses a signature database that maps combinations of
TTL, IP flags, TCP window size and TCP options to known OS families.
No active probe is sent; the fingerprint is derived entirely from packets
already received during the discovery and port scan phases.

The signatures below are simplified but cover the most common OS classes.
A full implementation would use a database like Nmap's nmap-os-db or p0f's
p0f.fp, but those files are not redistributed here.

References
----------
- p0f v3 technical documentation by Michal Zalewski
- Nmap OS detection engine (os_detection.cc)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TCPFingerprint:
    """Fields extracted from a SYN-ACK or ACK packet."""
    ttl:      int  = 0
    df_bit:   bool = False
    window:   int  = 0
    mss:      Optional[int] = None
    wscale:   Optional[int] = None
    sack_ok:  bool = False
    nop:      bool = False


@dataclass
class OSGuess:
    family:     str
    version:    str
    confidence: int   # 0 – 100


_SIGNATURES: list[tuple[dict, OSGuess]] = [
    # TTL, window, MSS → OS
    ({"ttl_range": (60, 65), "window": 65535},
     OSGuess("Linux", "2.4.x", 70)),
    ({"ttl_range": (60, 65), "window": (5700, 5792)},
     OSGuess("Linux", "3.x / 4.x", 80)),
    ({"ttl_range": (60, 65), "window": (29000, 29200), "wscale": (6, 8)},
     OSGuess("Linux", "5.x / 6.x", 85)),
    ({"ttl_range": (60, 65), "window": (14600, 14900)},
     OSGuess("Linux", "4.x–5.x (cloud / container)", 75)),
    ({"ttl_range": (126, 129), "window": (8192, 8192)},
     OSGuess("Windows", "XP / Server 2003", 80)),
    ({"ttl_range": (126, 129), "window": (65535, 65535)},
     OSGuess("Windows", "Vista / 7", 75)),
    ({"ttl_range": (126, 129), "window": (64240, 64240)},
     OSGuess("Windows", "10 / Server 2016+", 85)),
    ({"ttl_range": (126, 129), "window": (65535, 65535), "wscale": (8, 8)},
     OSGuess("Windows", "11 / Server 2022", 80)),
    ({"ttl_range": (252, 256), "window": (65535, 65535)},
     OSGuess("Cisco IOS", "12.x / 15.x", 75)),
    ({"ttl_range": (252, 256), "window": (4128, 4128)},
     OSGuess("Cisco IOS", "older", 70)),
    ({"ttl_range": (252, 256), "window": (8760, 8760)},
     OSGuess("Juniper JunOS", "any", 70)),
    ({"ttl_range": (60, 65), "window": (65535, 65535), "df_bit": True},
     OSGuess("macOS / FreeBSD", "10.x–13.x / 12.x", 70)),
    ({"ttl_range": (60, 65), "window": (65535, 65535), "df_bit": True,
      "wscale": (6, 6)},
     OSGuess("macOS", "Ventura / Sonoma", 80)),
    ({"ttl_range": (60, 65), "window": (65535, 65535), "df_bit": False},
     OSGuess("OpenBSD", "any", 65)),
]


def _ttl_initial_guess(observed_ttl: int) -> int:
    """
    Map an observed TTL to the most likely initial TTL value.

    Most OSes use 64, 128 or 255.  The observed TTL is always ≤ initial TTL
    (each router decrements by 1) so we round up to the nearest common value.
    """
    for initial in (64, 128, 255):
        if observed_ttl <= initial:
            return initial
    return 255


def _score_signature(fp: TCPFingerprint, sig: dict) -> int:
    score = 0
    ttl_init = _ttl_initial_guess(fp.ttl)

    if "ttl_range" in sig:
        lo, hi = sig["ttl_range"]
        if lo <= ttl_init <= hi:
            score += 30
        else:
            return 0

    if "window" in sig:
        w = sig["window"]
        if isinstance(w, tuple):
            lo, hi = w
            if lo <= fp.window <= hi:
                score += 25
        else:
            if fp.window == w:
                score += 25

    if "df_bit" in sig and fp.df_bit == sig["df_bit"]:
        score += 10

    if "mss" in sig and fp.mss is not None:
        lo, hi = sig["mss"]
        if lo <= fp.mss <= hi:
            score += 10

    if "wscale" in sig and fp.wscale is not None:
        lo, hi = sig["wscale"]
        if lo <= fp.wscale <= hi:
            score += 10

    if "sack_ok" in sig and fp.sack_ok == sig["sack_ok"]:
        score += 5

    return score


def fingerprint_os(fp: TCPFingerprint) -> OSGuess:
    """
    Return the best OS guess for the given TCP fingerprint.
    Returns OSGuess("Unknown", "", 0) when nothing matches.
    """
    best_score  = 0
    best_guess  = OSGuess("Unknown", "", 0)

    for sig, guess in _SIGNATURES:
        s = _score_signature(fp, sig)
        if s > best_score:
            best_score = s
            best_guess = OSGuess(
                family     = guess.family,
                version    = guess.version,
                confidence = min(100, int(s * guess.confidence / 85)),
            )

    return best_guess


def parse_tcp_options(raw_options: bytes) -> dict:
    """
    Parse TCP options from the variable-length option bytes.

    Returns a dict with keys: mss, wscale, sack_ok, ts_val, ts_ecr.
    """
    result: dict = {}
    i = 0
    while i < len(raw_options):
        kind = raw_options[i]
        if kind == 0:   # EOL
            break
        if kind == 1:   # NOP
            i += 1
            continue
        if i + 1 >= len(raw_options):
            break
        length = raw_options[i + 1]
        if length < 2 or i + length > len(raw_options):
            break
        data = raw_options[i + 2: i + length]

        if kind == 2 and len(data) == 2:    # MSS
            result["mss"] = struct.unpack("!H", data)[0]
        elif kind == 3 and len(data) == 1:  # Window Scale
            result["wscale"] = data[0]
        elif kind == 4:                     # SACK Permitted
            result["sack_ok"] = True
        elif kind == 8 and len(data) == 8:  # Timestamps
            result["ts_val"], result["ts_ecr"] = struct.unpack("!II", data)

        i += length

    return result


def extract_fingerprint_from_ip_packet(raw: bytes) -> TCPFingerprint | None:
    """
    Extract a TCPFingerprint from a raw IP packet (with IP header).
    Returns None if the packet is not a TCP SYN or SYN-ACK.
    """
    if len(raw) < 40:
        return None

    ihl      = (raw[0] & 0x0F) * 4
    ttl      = raw[8]
    flags_frag = struct.unpack("!H", raw[6:8])[0]
    df_bit   = bool(flags_frag & 0x4000)

    if len(raw) < ihl + 20:
        return None

    tcp = raw[ihl:]
    data_offset = (tcp[12] >> 4) * 4
    tcp_flags   = struct.unpack("!H", tcp[12:14])[0] & 0x3F
    window      = struct.unpack("!H", tcp[14:16])[0]

    # Only fingerprint SYN and SYN-ACK
    if not (tcp_flags & 0x02):
        return None

    options_raw = tcp[20:data_offset] if data_offset > 20 else b""
    opts = parse_tcp_options(options_raw)

    return TCPFingerprint(
        ttl     = ttl,
        df_bit  = df_bit,
        window  = window,
        mss     = opts.get("mss"),
        wscale  = opts.get("wscale"),
        sack_ok = opts.get("sack_ok", False),
    )
