"""Shared fixtures for the test suite."""

from __future__ import annotations

import time
from ipaddress import IPv4Network, IPv6Network

import pytest

from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import AS_SEQUENCE, AS_SET, ASPath, ASPathSegment, Route


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


_TS = int(time.time())


@pytest.fixture
def small_baseline() -> Baseline:
    """
    A minimal baseline covering five prefixes using real globally routable
    address space so the bogon detector never fires on clean routes.

      1.2.3.0/24   — AS64499 (single stable origin)
      8.8.8.0/24   — AS64500 (two peer paths, same origin)
      17.0.0.0/24  — AS64501
      8.8.8.0/25   — AS64500 (sub of /24)
    """
    b = Baseline()
    routes = [
        Route(IPv4Network("1.2.3.0/24"), 64499, _seq(64497, 64499), 64496, "1.2.3.1",   _TS),
        Route(IPv4Network("1.2.3.0/24"), 64499, _seq(64498, 64499), 64498, "1.2.3.2",   _TS),
        Route(IPv4Network("8.8.8.0/24"), 64500, _seq(64496, 64500), 64496, "8.8.8.1",   _TS),
        Route(IPv4Network("8.8.8.0/24"), 64500, _seq(64497, 64500), 64497, "8.8.8.2",   _TS),
        Route(IPv4Network("8.8.8.0/25"), 64500, _seq(64496, 64500), 64496, "8.8.8.1",   _TS),
        Route(IPv4Network("17.0.0.0/24"),64501, _seq(64498, 64501), 64498, "17.0.0.1",  _TS),
    ]
    for r in routes:
        b.add_route(r)
    return b


@pytest.fixture
def ts() -> int:
    return _TS
