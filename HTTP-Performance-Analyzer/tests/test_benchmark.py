import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import time
import pytest

from benchmark.metrics import RequestResult, ScenarioResult, _percentile


def _make_result(protocol, idx, total_time, ttfb=None, error=None):
    return RequestResult(
        protocol=protocol,
        url=f"http://localhost/test",
        status=200 if not error else 0,
        request_id=idx,
        start_time=time.time(),
        ttfb=ttfb if ttfb is not None else total_time * 0.3,
        total_time=total_time,
        bytes_received=1024,
        error=error,
    )


def _make_scenario(protocol, times, scenario="test", concurrency=1):
    reqs = [_make_result(protocol, i, t) for i, t in enumerate(times)]
    return ScenarioResult(
        protocol=protocol,
        scenario=scenario,
        concurrency=concurrency,
        n_requests=len(times),
        requests=reqs,
        wall_time=max(times) * 1.1 if times else 0.0,
    )


class TestRequestResult:
    def test_throughput_mbps(self):
        r = _make_result("HTTP/1.1", 0, total_time=1.0)
        r.bytes_received = 1_000_000   # 1 MB in 1 s = 8 Mbps
        assert abs(r.throughput_mbps - 8.0) < 0.01

    def test_zero_time(self):
        r = _make_result("HTTP/1.1", 0, total_time=0.0)
        assert r.throughput_mbps == 0.0


class TestScenarioResult:
    def test_percentiles(self):
        times = [0.1, 0.2, 0.3, 0.4, 0.5]
        s = _make_scenario("HTTP/2", times)
        assert 0.2 <= s.latency_p50 <= 0.4
        assert s.latency_p95 >= s.latency_p50
        assert s.latency_p99 >= s.latency_p95

    def test_rps(self):
        s = _make_scenario("HTTP/1.1", [0.1] * 10)
        s.wall_time = 1.0
        assert abs(s.rps - 10.0) < 0.1

    def test_errors_excluded_from_stats(self):
        reqs = [_make_result("HTTP/1.1", 0, 0.1)] * 4 + \
               [_make_result("HTTP/1.1", 4, 0.0, error="timeout")]
        s = ScenarioResult(
            protocol="HTTP/1.1", scenario="t", concurrency=1,
            n_requests=5, requests=reqs, wall_time=1.0, errors=1,
        )
        assert s.n_ok == 4
        assert s.latency_p50 > 0

    def test_to_dict_keys(self):
        s = _make_scenario("HTTP/2", [0.05, 0.1, 0.15])
        d = s.to_dict()
        for key in ("protocol", "scenario", "rps", "ttfb_p50_ms", "latency_p50_ms", "waterfall"):
            assert key in d

    def test_waterfall_length_matches_requests(self):
        s = _make_scenario("HTTP/2", [0.1] * 5)
        assert len(s.to_dict()["waterfall"]) == 5

    def test_mean_latency(self):
        times = [0.1, 0.2, 0.3]
        s = _make_scenario("HTTP/3", times)
        assert abs(s.mean_latency - 0.2) < 0.01

    def test_primary_category_empty(self):
        s = _make_scenario("HTTP/1.1", [])
        assert s.n_ok == 0


class TestPercentileHelper:
    def test_p50(self):
        reqs = [_make_result("HTTP/1.1", i, float(i + 1) / 10) for i in range(10)]
        assert abs(_percentile(reqs, "total_time", 50) - 0.5) < 0.15

    def test_empty(self):
        assert _percentile([], "total_time", 50) == 0.0

    def test_single(self):
        r = [_make_result("HTTP/2", 0, 0.42)]
        assert _percentile(r, "total_time", 50) == pytest.approx(0.42)


class TestAnalysisStats:
    def setup_method(self):
        from analysis.stats import group_by_scenario, speedup_table
        self.group     = group_by_scenario
        self.speedup   = speedup_table

    def test_group_by_scenario(self):
        h1 = _make_scenario("HTTP/1.1", [0.1], scenario="a")
        h2 = _make_scenario("HTTP/2",   [0.05], scenario="a")
        h3 = _make_scenario("HTTP/1.1", [0.2], scenario="b")
        groups = self.group([h1, h2, h3])
        assert set(groups.keys()) == {"a", "b"}
        assert len(groups["a"]) == 2

    def test_speedup_table_h2_faster(self):
        h1 = _make_scenario("HTTP/1.1", [0.2] * 10, scenario="s")
        h1.wall_time = 2.0
        h2 = _make_scenario("HTTP/2",   [0.1] * 10, scenario="s")
        h2.wall_time = 1.0
        rows = self.speedup([h1, h2])
        assert len(rows) == 1
        assert rows[0]["h2_speedup"] == pytest.approx(2.0)

    def test_speedup_table_no_h2(self):
        h1 = _make_scenario("HTTP/1.1", [0.1], scenario="x")
        rows = self.speedup([h1])
        assert rows[0]["h2_speedup"] is None


class TestServerApp:
    """Unit tests for the ASGI test application without a running server."""

    def test_small_response_length(self):
        from server.app import _SMALL_BODY
        assert len(_SMALL_BODY) == 1024

    def test_medium_response_length(self):
        from server.app import _MEDIUM_BODY
        assert len(_MEDIUM_BODY) == 100 * 1024

    def test_large_response_length(self):
        from server.app import _LARGE_BODY
        assert len(_LARGE_BODY) == 1024 * 1024

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        from server.app import app

        sends = []
        async def mock_send(event):
            sends.append(event)

        await app(
            {"type": "http", "method": "GET", "path": "/health", "query_string": b"", "headers": []},
            None,
            mock_send,
        )
        assert sends[0]["status"] == 200
        assert sends[1]["body"] == b"ok"

    @pytest.mark.asyncio
    async def test_small_endpoint(self):
        from server.app import app, _SMALL_BODY

        sends = []
        async def mock_send(event):
            sends.append(event)

        await app(
            {"type": "http", "method": "GET", "path": "/small", "query_string": b"", "headers": []},
            None,
            mock_send,
        )
        assert sends[0]["status"] == 200
        assert sends[1]["body"] == _SMALL_BODY

    @pytest.mark.asyncio
    async def test_404_endpoint(self):
        from server.app import app

        sends = []
        async def mock_send(event):
            sends.append(event)

        await app(
            {"type": "http", "method": "GET", "path": "/nonexistent", "query_string": b"", "headers": []},
            None,
            mock_send,
        )
        assert sends[0]["status"] == 404

    @pytest.mark.asyncio
    async def test_resources_endpoint(self):
        from server.app import app
        import json

        sends = []
        async def mock_send(event):
            sends.append(event)

        await app(
            {"type": "http", "method": "GET", "path": "/resources",
             "query_string": b"n=5&size=2", "headers": []},
            None,
            mock_send,
        )
        assert sends[0]["status"] == 200
        data = json.loads(sends[1]["body"])
        assert len(data["urls"]) == 5
        assert all("size=2" not in u or "/resource/2" in u for u in data["urls"])
