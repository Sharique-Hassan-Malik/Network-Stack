"""
AS number and prefix classification.

Private/reserved AS ranges per RFC 6996, RFC 7607 and RFC 5398.
Bogon prefixes per IANA special-purpose address registries.
Tier-1 ASN set used as a heuristic anchor for route leak detection.
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network
from typing import Union

IPNetwork = Union[IPv4Network, IPv6Network]

# Private and reserved AS number ranges (inclusive)
PRIVATE_ASN_RANGES: tuple[tuple[int, int], ...] = (
    (0,           0),            # Reserved
    (23456,       23456),        # AS_TRANS placeholder (RFC 6793)
    (64512,       65534),        # Private use (RFC 6996)
    (65535,       65535),        # Reserved
    (4200000000,  4294967294),   # 4-byte private use (RFC 6996)
    (4294967295,  4294967295),   # Reserved
)

TIER1_ASNS: frozenset[int] = frozenset({
    174,    # Cogent
    209,    # Lumen / CenturyLink
    286,    # KPN
    701,    # Verizon / UUNet
    702,    # Verizon Business
    1239,   # Sprint
    1273,   # Vodafone
    1299,   # Telia
    2914,   # NTT
    3257,   # GTT
    3320,   # Deutsche Telekom
    3356,   # Lumen / Level 3
    3491,   # PCCW Global
    4134,   # China Telecom
    5511,   # Orange
    6453,   # Tata Communications
    6461,   # Zayo
    6762,   # Telecom Italia Sparkle
    6830,   # Liberty Global
    7018,   # AT&T
    7922,   # Comcast
    12956,  # Telefonica
})

_BOGON_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
]

_BOGON_V6 = [
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "100::/64",
    "2001::/32",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

BOGON_V4: tuple[IPv4Network, ...] = tuple(IPv4Network(s) for s in _BOGON_V4)
BOGON_V6: tuple[IPv6Network, ...] = tuple(IPv6Network(s) for s in _BOGON_V6)


def is_bogon_asn(asn: int) -> bool:
    return any(lo <= asn <= hi for lo, hi in PRIVATE_ASN_RANGES)


def is_private_asn(asn: int) -> bool:
    return (64512 <= asn <= 65534) or (4200000000 <= asn <= 4294967294)


def bogon_asn_reason(asn: int) -> str:
    if asn == 0:
        return "reserved (AS 0)"
    if asn == 23456:
        return "AS_TRANS placeholder (RFC 6793)"
    if 64512 <= asn <= 65534:
        return "private use (RFC 6996)"
    if asn == 65535:
        return "reserved (AS 65535)"
    if 4200000000 <= asn <= 4294967294:
        return "4-byte private range (RFC 6996)"
    if asn == 4294967295:
        return "reserved (AS 4294967295)"
    return "bogon"


def is_bogon_prefix(prefix: IPNetwork) -> tuple[bool, str]:
    """Return (is_bogon, matching_bogon_range_str)."""
    if isinstance(prefix, IPv4Network):
        for bogon in BOGON_V4:
            if prefix.overlaps(bogon):
                return True, str(bogon)
    else:
        for bogon in BOGON_V6:
            if prefix.overlaps(bogon):
                return True, str(bogon)
    return False, ""
