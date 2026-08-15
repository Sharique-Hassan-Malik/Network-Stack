from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from bgp_analyzer.analyzer import BGPHijackAnalyzer, DetectorConfig
from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import AS_SEQUENCE, ASPath, ASPathSegment, Route
from bgp_analyzer.detectors.path_anomaly import PathAnomalyDetector
from bgp_analyzer.detectors.route_leak import RouteLeakDetector


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


def _route(prefix: str, origin: int, *asns: int, ts: int = 1000) -> Route:
    return Route(
        IPv4Network(prefix), origin, _seq(*asns),
        asns[0] if asns else None, "1.1.1.1", ts,
    )


class TestPathAnomalyDetector:

    def setup_method(self):
        self.det = PathAnomalyDetector()

    def test_loop_detected(self, small_baseline):
        route = _route("1.2.3.0/24", 64499, 64497, 64497, 64499)
        alerts = list(self.det.check(route, small_baseline))
        assert any(a.kind == "path_loop" for a in alerts)

    def test_no_loop_for_clean_path(self, small_baseline):
        route = _route("1.2.3.0/24", 64499, 64496, 64497, 64499)
        alerts = [a for a in self.det.check(route, small_baseline) if a.kind == "path_loop"]
        assert alerts == []

    def test_private_asn_leak(self, small_baseline):
        route = _route("17.0.0.0/24", 64501, 64498, 65000, 64501)
        alerts = list(self.det.check(route, small_baseline))
        assert any(a.kind == "path_anomaly" for a in alerts)
        pa = next(a for a in alerts if a.kind == "path_anomaly")
        assert 65000 in pa.extra["private_asns"]

    def test_no_alert_for_public_path(self, small_baseline):
        route = _route("17.0.0.0/24", 64501, 64498, 64501)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts == []

    def test_no_alert_without_path(self, small_baseline):
        r = Route(IPv4Network("1.2.3.0/24"), 64499, None, None, None, 1000)
        assert list(self.det.check(r, small_baseline)) == []


class TestRouteLeakDetector:

    def setup_method(self):
        self.det = RouteLeakDetector()

    def test_alert_on_path_length_excess(self, small_baseline):
        # baseline average for 1.2.3.0/24 is 2 hops; 8-hop path should fire
        route = _route("1.2.3.0/24", 64499, 64496, 64497, 64498, 64497, 64496, 64498, 64497, 64499)
        alerts = list(self.det.check(route, small_baseline))
        assert any(a.kind == "route_leak" for a in alerts)

    def test_no_alert_for_normal_path_length(self, small_baseline):
        route = _route("1.2.3.0/24", 64499, 64497, 64499)
        alerts = list(self.det.check(route, small_baseline))
        assert alerts == []

    def test_no_alert_for_unknown_prefix(self, small_baseline):
        route = _route("5.5.5.0/24", 64503, 64496, 64503)
        assert list(self.det.check(route, small_baseline)) == []


class TestBGPHijackAnalyzer:

    def test_demo_attacked_produces_alerts(self):
        from bgp_analyzer.generator import baseline_routes, current_routes_attacked

        baseline = Baseline.build(baseline_routes())
        analyzer = BGPHijackAnalyzer()

        class _FakeResult:
            pass

        # Bypass file loading by patching at module level temporarily
        import bgp_analyzer.analyzer as _mod
        orig = _mod.load_routes

        def _fake(_path):
            return current_routes_attacked()

        _mod.load_routes = _fake
        try:
            result = analyzer.analyze(baseline, "/dev/null")
        finally:
            _mod.load_routes = orig

        assert len(result.alerts) > 0
        kinds = {a.kind for a in result.alerts}
        assert "origin_hijack"    in kinds
        assert "subprefix_hijack" in kinds
        assert "bogon_prefix"     in kinds

    def test_demo_clean_produces_no_alerts(self):
        from bgp_analyzer.generator import baseline_routes, current_routes_clean

        baseline = Baseline.build(baseline_routes())
        analyzer = BGPHijackAnalyzer()

        import bgp_analyzer.analyzer as _mod
        orig = _mod.load_routes

        def _fake(_path):
            return current_routes_clean()

        _mod.load_routes = _fake
        try:
            result = analyzer.analyze(baseline, "/dev/null")
        finally:
            _mod.load_routes = orig

        high_and_medium = [
            a for a in result.alerts
            if a.severity in ("high", "medium")
        ]
        assert high_and_medium == []

    def test_detector_config_disables_detector(self):
        from bgp_analyzer.generator import baseline_routes, current_routes_attacked

        baseline = Baseline.build(baseline_routes())
        cfg      = DetectorConfig(
            origin_hijack=False,
            subprefix_hijack=False,
            route_leak=False,
            bogon=False,
            path_anomaly=False,
        )
        analyzer = BGPHijackAnalyzer(cfg)

        import bgp_analyzer.analyzer as _mod
        orig = _mod.load_routes

        def _fake(_path):
            return current_routes_attacked()

        _mod.load_routes = _fake
        try:
            result = analyzer.analyze(baseline, "/dev/null")
        finally:
            _mod.load_routes = orig

        assert result.alerts == []

    def test_result_by_severity_structure(self):
        from bgp_analyzer.generator import baseline_routes, current_routes_attacked
        from bgp_analyzer.core.baseline import Baseline

        baseline = Baseline.build(baseline_routes())
        analyzer = BGPHijackAnalyzer()

        import bgp_analyzer.analyzer as _mod
        orig = _mod.load_routes
        _mod.load_routes = lambda _: current_routes_attacked()
        try:
            result = analyzer.analyze(baseline, "/dev/null")
        finally:
            _mod.load_routes = orig

        sev = result.by_severity
        assert set(sev.keys()) == {"high", "medium", "low", "info"}
