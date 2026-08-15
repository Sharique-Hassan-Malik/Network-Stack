"""One way to report a measurement, for every tool in this repository.

Six tools that all measure latency, and six ways of saying so: one computed
percentiles by index into a sorted list, another by interpolation, a third
reported only a mean. Numbers from different tools could not be put in the same
table, which is exactly what you want to do when comparing a transport against
HTTP/3 or a probe against a benchmark.

`Measurement` holds the raw samples and derives everything from them. Keeping
the samples rather than only the summary is deliberate: a p99 cannot be
recomputed from a mean, and merging two summaries is not the same as summarising
the union.

Stdlib only.
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence


def percentile(values: Sequence[float], pct: float) -> float:
    """Linear-interpolated percentile, the definition NumPy and most tools use.

    Nearest-rank — the other common choice — disagrees by a whole sample on
    small batches, which is exactly the regime a benchmark of 50 requests is
    in, so the two are not interchangeable and the choice is written down here
    once.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])

    rank = (pct / 100.0) * (len(ordered) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(ordered[int(rank)])
    return float(ordered[low] + (ordered[high] - ordered[low]) * (rank - low))


@dataclass
class Measurement:
    """A named series of samples, and the statistics anything would want."""

    name: str
    samples: list[float] = field(default_factory=list)
    unit: str = "ms"
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, value: float) -> None:
        self.samples.append(float(value))

    def extend(self, values: Iterable[float]) -> None:
        self.samples.extend(float(v) for v in values)

    def __len__(self) -> int:
        return len(self.samples)

    def __bool__(self) -> bool:
        return bool(self.samples)

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples) if self.samples else 0.0

    @property
    def stdev(self) -> float:
        return statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def minimum(self) -> float:
        return min(self.samples) if self.samples else 0.0

    @property
    def maximum(self) -> float:
        return max(self.samples) if self.samples else 0.0

    def p(self, pct: float) -> float:
        return percentile(self.samples, pct)

    @property
    def p50(self) -> float:
        return self.p(50)

    @property
    def p95(self) -> float:
        return self.p(95)

    @property
    def p99(self) -> float:
        return self.p(99)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "unit": self.unit,
            "count": self.count,
            "mean": round(self.mean, 4),
            "p50": round(self.p50, 4),
            "p95": round(self.p95, 4),
            "p99": round(self.p99, 4),
            "min": round(self.minimum, 4),
            "max": round(self.maximum, 4),
            "stdev": round(self.stdev, 4),
            **({"metadata": self.metadata} if self.metadata else {}),
        }

    def row(self) -> str:
        """One fixed-width line — what the CLIs print."""
        return (
            f"{self.name:<28} {self.count:>6}  "
            f"p50 {self.p50:>9.2f}  p95 {self.p95:>9.2f}  "
            f"p99 {self.p99:>9.2f}  mean {self.mean:>9.2f} {self.unit}"
        )


@dataclass
class Run:
    """One tool's output: measurements, plus whatever scalar facts it has."""

    tool: str
    target: str = ""
    measurements: list[Measurement] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    skipped: str = ""

    def measure(self, name: str, unit: str = "ms", **metadata: Any) -> Measurement:
        measurement = Measurement(name=name, unit=unit, metadata=metadata)
        self.measurements.append(measurement)
        return measurement

    @property
    def ran(self) -> bool:
        return not self.error and not self.skipped

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": self.tool,
            "target": self.target,
            "measurements": [m.summary() for m in self.measurements],
        }
        if self.facts:
            out["facts"] = self.facts
        if self.error:
            out["error"] = self.error
        if self.skipped:
            out["skipped"] = self.skipped
        return out


@dataclass
class Report:
    """Several runs, comparable because they share one measurement type."""

    title: str = ""
    runs: list[Run] = field(default_factory=list)

    def add(self, run: Run) -> Run:
        self.runs.append(run)
        return run

    @property
    def errors(self) -> list[Run]:
        return [r for r in self.runs if r.error]

    @property
    def exit_code(self) -> int:
        return 2 if self.errors else 0

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "runs": [r.to_dict() for r in self.runs]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
