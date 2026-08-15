from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from bgp_analyzer.core.types import AS_SEQUENCE, ASPath, ASPathSegment, Route
from bgp_analyzer.detectors.origin_hijack import OriginHijackDetector


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


def _route(prefix: str, origin: int, path_asns: tuple[int, ...], ts: int = 1000) -> Route:
    return Route(
        prefix=IPv4Network(prefix),
        origin_as=origin,
        as_path=_seq(*path_asns),
        peer_as=path_asns[0] if path_asns else None,
        peer_ip="1.1.1.1",
        timestamp=ts,
    )


class TestOriginHijackDetector:

    def setup_method(self):
        self.detector = OriginHijackDetector()

    def test_no_alert_for_known_origin(self, small_baseline):
        route = _route("1.2.3.0/24", 64499, (64497, 64499))
        alerts = list(self.detector.check(route, small_baseline))
        assert alerts == []

    def test_high_alert_for_unknown_origin_single_known(self, small_baseline):
        # 1.2.3.0/24 has only AS64499 in baseline
        route = _route("1.2.3.0/24", 64503, (64497, 64503))
        alerts = list(self.detector.check(route, small_baseline))
        assert len(alerts) == 1
        assert alerts[0].kind == "origin_hijack"
        assert alerts[0].severity == "high"
        assert alerts[0].extra["new_origin"] == 64503

    def test_medium_alert_for_prefix_with_many_origins(self, small_baseline):
        # Insert many extra origins for 198.51.100.0/24 to trigger medium severity
        from bgp_analyzer.core.baseline import Baseline
        b = Baseline()
        for asn in range(64499, 64510):
            r = _route("198.51.100.0/24", asn, (64496, asn))
            b.add_route(r)
        route = _route("198.51.100.0/24", 64520, (64496, 64520))
        alerts = list(self.detector.check(route, b))
        assert len(alerts) == 1
        assert alerts[0].severity == "medium"

    def test_no_alert_when_prefix_not_in_baseline(self, small_baseline):
        route = _route("5.5.5.0/24", 64503, (64496, 64503))
        alerts = list(self.detector.check(route, small_baseline))
        assert alerts == []

    def test_no_alert_when_origin_as_is_none(self, small_baseline):
        route = Route(
            prefix=IPv4Network("1.2.3.0/24"),
            origin_as=None,
            as_path=None,
            peer_as=None,
            peer_ip=None,
            timestamp=1000,
        )
        alerts = list(self.detector.check(route, small_baseline))
        assert alerts == []

    def test_known_origins_in_extra(self, small_baseline):
        route = _route("1.2.3.0/24", 64503, (64497, 64503))
        alerts = list(self.detector.check(route, small_baseline))
        assert 64499 in alerts[0].extra["known_origins"]
