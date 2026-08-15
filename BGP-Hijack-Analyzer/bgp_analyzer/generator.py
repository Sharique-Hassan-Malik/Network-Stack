"""
Synthetic route generator.

Produces deterministic, realistic BGP routes for testing and the --demo
CLI mode.  All prefixes and ASNs are drawn from documentation / example
ranges so they can never clash with real global table data.

Eight simulated ASes form a small stub internet:
  AS64496 — upstream transit provider (simulated Tier-1 stub)
  AS64497 — regional ISP connected to AS64496
  AS64498 — another regional ISP connected to AS64496
  AS64499 — enterprise customer of AS64497 owning 192.0.2.0/24
  AS64500 — CDN owning 198.51.100.0/25 and 198.51.100.128/25
  AS64501 — enterprise customer of AS64498
  AS64502 — small ISP peering with AS64497 and AS64498
  AS64503 — attacker AS injected only in current_routes

Baseline routes: legitimate announcements from AS64496–AS64502.
Current routes (no attack): identical to baseline.
Current routes (with attack): baseline + injected hijacks.

Injected attacks in demo mode:
  origin_hijack    — AS64503 announces 192.0.2.0/24 (owned by AS64499)
  subprefix_hijack — AS64503 announces 198.51.100.64/26 (sub of AS64500 prefix)
  bogon_prefix     — AS64503 announces 10.0.0.0/8
  bogon_as         — 192.0.2.0/24 path contains AS64512 (private range)
  path_anomaly     — legitimate path with a repeated AS (loop)
  route_leak       — abnormally long path for 198.51.100.0/25
"""

from __future__ import annotations

import time
from ipaddress import IPv4Network
from typing import Iterator

from bgp_analyzer.core.types import AS_SEQUENCE, ASPath, ASPathSegment, Route


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


_TS = int(time.time())

# Using real globally routable prefixes (APNIC, ARIN, Cloudflare ranges)
# so the bogon detector never fires on legitimate baseline/clean routes.
_BASELINE: list[Route] = [
    # AS64499 owns 1.2.3.0/24 — path through AS64497 and AS64496
    Route(IPv4Network("1.2.3.0/24"),   64499, _seq(64497, 64499), 64496, "1.2.3.1",   _TS),
    Route(IPv4Network("1.2.3.0/24"),   64499, _seq(64498, 64497, 64499), 64498, "1.2.3.2", _TS),
    # AS64500 CDN prefixes
    Route(IPv4Network("8.8.8.0/25"),   64500, _seq(64496, 64500), 64496, "8.8.8.1",   _TS),
    Route(IPv4Network("8.8.8.128/25"), 64500, _seq(64496, 64500), 64496, "8.8.8.1",   _TS),
    # AS64501
    Route(IPv4Network("17.0.0.0/24"),  64501, _seq(64498, 64501), 64496, "17.0.0.1",  _TS),
    # AS64502 peer prefix
    Route(IPv4Network("17.0.0.128/25"),64502, _seq(64497, 64502), 64497, "17.0.0.2",  _TS),
    # AS64497 infrastructure
    Route(IPv4Network("9.0.0.0/8"),    64497, _seq(64497,),       64497, "9.0.0.1",   _TS),
]

_ATTACKS: list[Route] = [
    # origin_hijack: AS64503 announces 1.2.3.0/24 (owned by AS64499)
    Route(IPv4Network("1.2.3.0/24"),    64503, _seq(64497, 64503), 64497, "1.2.3.99",  _TS),
    # subprefix_hijack: AS64503 announces /26 under AS64500's /25
    Route(IPv4Network("8.8.8.64/26"),   64503, _seq(64496, 64503), 64496, "8.8.8.99",  _TS),
    # bogon_prefix: 10.0.0.0/8 in global table
    Route(IPv4Network("10.0.0.0/8"),    64503, _seq(64496, 64503), 64496, "10.0.0.1",  _TS),
    # bogon_as: legitimate prefix, private ASN in path
    Route(IPv4Network("17.0.0.0/24"),   64501, _seq(64512, 64501), 64496, "17.0.0.1",  _TS),
    # path_loop: AS64497 appears twice
    Route(IPv4Network("8.8.8.0/25"),    64500, _seq(64497, 64497, 64500), 64496, "8.8.8.1", _TS),
    # route_leak: 17.0.0.128/25 via 8-hop path (avg is 2)
    Route(
        IPv4Network("17.0.0.128/25"), 64502,
        _seq(64496, 64497, 64498, 64497, 64496, 64498, 64497, 64502),
        64497, "17.0.0.2", _TS,
    ),
]


def baseline_routes() -> Iterator[Route]:
    yield from _BASELINE


def current_routes_clean() -> Iterator[Route]:
    yield from _BASELINE


def current_routes_attacked() -> Iterator[Route]:
    yield from _BASELINE
    yield from _ATTACKS
