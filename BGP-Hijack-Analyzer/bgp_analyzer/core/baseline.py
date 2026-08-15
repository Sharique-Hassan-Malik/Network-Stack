"""
Baseline builder and per-prefix profile store.

For each prefix the baseline records:
  - all observed origin ASes
  - all observed peer ASes
  - sample AS path strings (up to 20)
  - route count and a few sample Route objects

The baseline is intentionally additive: all routes from a historical file
are folded in so that multiple origin ASes seen over time are preserved
and do not produce false positives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Union

from ipaddress import IPv4Network, IPv6Network

from bgp_analyzer.core.types import Route
from bgp_analyzer.core.trie import PrefixTrie

IPNetwork = Union[IPv4Network, IPv6Network]

_MAX_SAMPLE_ROUTES = 5
_MAX_SAMPLE_PATHS  = 20


@dataclass
class PrefixProfile:
    prefix: IPNetwork
    origin_ases: set[int]  = field(default_factory=set)
    peer_ases: set[int]    = field(default_factory=set)
    as_paths: list[str]    = field(default_factory=list)
    route_count: int       = 0
    sample_routes: list[Route] = field(default_factory=list)

    def add_route(self, route: Route) -> None:
        self.route_count += 1
        if route.origin_as is not None:
            self.origin_ases.add(route.origin_as)
        if route.peer_as is not None:
            self.peer_ases.add(route.peer_as)
        path = route.path_str
        if path and path not in self.as_paths and len(self.as_paths) < _MAX_SAMPLE_PATHS:
            self.as_paths.append(path)
        if len(self.sample_routes) < _MAX_SAMPLE_ROUTES:
            self.sample_routes.append(route)

    @property
    def avg_path_length(self) -> float:
        lengths = [
            r.as_path.length
            for r in self.sample_routes
            if r.as_path is not None
        ]
        return sum(lengths) / len(lengths) if lengths else 0.0


class Baseline:
    """
    Per-prefix profile store built from one or more historical RIB dumps.
    Maintains a prefix trie for fast sub-prefix and covering-prefix queries.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, PrefixProfile] = {}
        self._trie = PrefixTrie()
        self.total_routes   = 0
        self.total_prefixes = 0

    def _key(self, prefix: IPNetwork) -> str:
        return str(prefix)

    def add_route(self, route: Route) -> None:
        self.total_routes += 1
        key = self._key(route.prefix)
        if key not in self._profiles:
            self._profiles[key] = PrefixProfile(prefix=route.prefix)
            self._trie.insert(route.prefix)
            self.total_prefixes += 1
        self._profiles[key].add_route(route)

    def get_profile(self, prefix: IPNetwork) -> Optional[PrefixProfile]:
        return self._profiles.get(str(prefix))

    def has_prefix(self, prefix: IPNetwork) -> bool:
        return str(prefix) in self._profiles

    def covering_prefixes(self, prefix: IPNetwork) -> list[IPNetwork]:
        return self._trie.covering_prefixes(prefix)

    def more_specific_prefixes(self, prefix: IPNetwork) -> list[IPNetwork]:
        return self._trie.more_specific_prefixes(prefix)

    def iter_profiles(self) -> Iterator[PrefixProfile]:
        yield from self._profiles.values()

    @classmethod
    def build(cls, routes: Iterator[Route]) -> "Baseline":
        b = cls()
        for route in routes:
            b.add_route(route)
        return b
