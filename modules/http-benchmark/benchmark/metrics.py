from __future__ import annotations

import sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from netcore.measure import percentile  # noqa: E402

from dataclasses import dataclass, field
from typing import Literal


Protocol = Literal["HTTP/1.1", "HTTP/2", "HTTP/3"]


@dataclass
class RequestResult:
    """Timing and metadata for a single HTTP request."""
    protocol:         Protocol
    url:              str
    status:           int
    request_id:       int           # 0-based index within the batch
    start_time:       float         # absolute epoch seconds
    ttfb:             float         # time-to-first-byte (seconds)
    total_time:       float         # full response time (seconds)
    bytes_received:   int
    error:            str | None = None

    @property
    def throughput_mbps(self) -> float:
        if self.total_time <= 0:
            return 0.0
        return (self.bytes_received * 8) / (self.total_time * 1_000_000)


@dataclass
class ScenarioResult:
    """Aggregated results for one benchmark scenario on one protocol."""
    protocol:        Protocol
    scenario:        str
    concurrency:     int
    n_requests:      int
    requests:        list[RequestResult]
    wall_time:       float          # total elapsed wall-clock time for the batch
    errors:          int = 0

    # Computed lazily
    _sorted: list[RequestResult] | None = field(default=None, repr=False, compare=False)

    def _ok(self) -> list[RequestResult]:
        if self._sorted is None:
            self._sorted = sorted(
                [r for r in self.requests if r.error is None],
                key=lambda r: r.total_time,
            )
        return self._sorted

    @property
    def n_ok(self) -> int:
        return len(self._ok())

    @property
    def ttfb_p50(self) -> float:
        return _percentile(self._ok(), "ttfb", 50)

    @property
    def ttfb_p95(self) -> float:
        return _percentile(self._ok(), "ttfb", 95)

    @property
    def ttfb_p99(self) -> float:
        return _percentile(self._ok(), "ttfb", 99)

    @property
    def latency_p50(self) -> float:
        return _percentile(self._ok(), "total_time", 50)

    @property
    def latency_p95(self) -> float:
        return _percentile(self._ok(), "total_time", 95)

    @property
    def latency_p99(self) -> float:
        return _percentile(self._ok(), "total_time", 99)

    @property
    def mean_latency(self) -> float:
        ok = self._ok()
        return sum(r.total_time for r in ok) / len(ok) if ok else 0.0

    @property
    def rps(self) -> float:
        return self.n_ok / self.wall_time if self.wall_time > 0 else 0.0

    @property
    def mean_throughput_mbps(self) -> float:
        ok = self._ok()
        return sum(r.throughput_mbps for r in ok) / len(ok) if ok else 0.0

    def to_dict(self) -> dict:
        return {
            "protocol":          self.protocol,
            "scenario":          self.scenario,
            "concurrency":       self.concurrency,
            "n_requests":        self.n_requests,
            "n_ok":              self.n_ok,
            "errors":            self.errors,
            "wall_time":         round(self.wall_time, 4),
            "rps":               round(self.rps, 2),
            "ttfb_p50_ms":       round(self.ttfb_p50 * 1000, 2),
            "ttfb_p95_ms":       round(self.ttfb_p95 * 1000, 2),
            "ttfb_p99_ms":       round(self.ttfb_p99 * 1000, 2),
            "latency_p50_ms":    round(self.latency_p50 * 1000, 2),
            "latency_p95_ms":    round(self.latency_p95 * 1000, 2),
            "latency_p99_ms":    round(self.latency_p99 * 1000, 2),
            "mean_latency_ms":   round(self.mean_latency * 1000, 2),
            "mean_throughput_mbps": round(self.mean_throughput_mbps, 3),
            "waterfall":         [
                {
                    "id":         r.request_id,
                    "start_ms":   round((r.start_time - self.requests[0].start_time) * 1000, 2),
                    "ttfb_ms":    round(r.ttfb * 1000, 2),
                    "total_ms":   round(r.total_time * 1000, 2),
                    "bytes":      r.bytes_received,
                    "status":     r.status,
                    "error":      r.error,
                }
                for r in self.requests
            ],
        }


def _percentile(results: list[RequestResult], attr: str, pct: int) -> float:
    """Percentiles come from `netcore.measure`, shared with the rest of the repo.

    The index arithmetic this replaced — `int(len * pct / 100) - 1` — under-
    reported the tail on small batches: for ten requests it returned the ninth
    value as the p99 and the fifth as the p50. Tail latency is the number a
    benchmark exists to report, so the definition is now written down once and
    used by every tool here.
    """
    if not results:
        return 0.0
    return percentile([getattr(r, attr) for r in results], pct)
