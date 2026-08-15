from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

import pytest

from bgp_analyzer.core.types import AS_SEQUENCE, ASPath, ASPathSegment, Route
from bgp_analyzer.detectors.bogon import BogonDetector
from bgp_analyzer.detectors.subprefix import SubprefixHijackDetector


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


def _route(prefix: str, origin: int, *asns: int) -> Route:
    net = IPv4Network(prefix) if "." in prefix else IPv6Network(prefix)
    return Route(net, origin, _seq(*asns), asns[0] if asns else None, "1.1.1.1", 1000)


class TestSubprefixHijackDetector:

    def setup_method(self):
        self.det = SubprefixHijackDetector()

    def test_no_alert_when_prefix_in_baseline(self, small_baseline):
        # exact match — origin hijack handles it, not this detector
        route = _route("1.2.3.0/24", 64503, 64497, 64503)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts == []

    def test_no_alert_when_no_covering_prefix(self, small_baseline):
        route = _route("5.5.5.0/24", 64503, 64496, 64503)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts == []

    def test_alert_for_more_specific_by_different_as(self, small_baseline):
        # /26 under 1.2.3.0/24 (owned by AS64499), announced by AS64503
        route = _route("1.2.3.0/26", 64503, 64497, 64503)
        alerts = list(self.det.check(route, small_baseline))
        assert len(alerts) == 1
        assert alerts[0].kind == "subprefix_hijack"
        assert alerts[0].extra["covering_prefix"] == "1.2.3.0/24"
        assert 64499 in alerts[0].extra["covering_origins"]

    def test_no_alert_when_covering_as_is_same(self, small_baseline):
        # AS64499 legitimately disaggregates its own prefix — should be clean
        route = _route("1.2.3.0/26", 64499, 64497, 64499)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts == []

    def test_host_route_is_high_severity(self, small_baseline):
        route = _route("1.2.3.1/32", 64503, 64497, 64503)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts[0].severity == "high"

    def test_no_alert_when_origin_none(self, small_baseline):
        r = Route(IPv4Network("1.2.3.0/26"), None, None, None, None, 1000)
        assert list(self.det.check(r, small_baseline)) == []


class TestBogonDetector:

    def setup_method(self):
        self.det = BogonDetector()

    def test_alert_for_rfc1918_prefix(self, small_baseline):
        route = _route("10.0.0.0/8", 64503, 64496, 64503)
        alerts = list(self.det.check(route, small_baseline))
        kinds = [a.kind for a in alerts]
        assert "bogon_prefix" in kinds

    def test_alert_for_loopback(self, small_baseline):
        route = _route("127.0.0.0/8", 64503, 64496, 64503)
        alerts = list(self.det.check(route, small_baseline))
        assert any(a.kind == "bogon_prefix" for a in alerts)

    def test_no_alert_for_public_prefix(self, small_baseline):
        route = _route("1.2.3.0/24", 64499, 64497, 64499)
        alerts = [a for a in self.det.check(route, small_baseline) if a.kind == "bogon_prefix"]
        assert alerts == []

    def test_alert_for_bogon_asn_in_path(self, small_baseline):
        route = _route("17.0.0.0/24", 64501, 64512, 64501)  # AS64512 is private
        alerts = list(self.det.check(route, small_baseline))
        assert any(a.kind == "bogon_as" for a in alerts)

    def test_no_alert_for_clean_path(self, small_baseline):
        route = _route("17.0.0.0/24", 64501, 64498, 64501)
        alerts = [a for a in self.det.check(route, small_baseline) if a.kind == "bogon_as"]
        assert alerts == []
