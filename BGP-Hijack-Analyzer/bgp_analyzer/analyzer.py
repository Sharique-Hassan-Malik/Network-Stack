"""
BGPHijackAnalyzer — orchestrates baseline building and multi-detector analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert
from bgp_analyzer.detectors.base import BaseDetector
from bgp_analyzer.detectors.bogon import BogonDetector
from bgp_analyzer.detectors.origin_hijack import OriginHijackDetector
from bgp_analyzer.detectors.path_anomaly import PathAnomalyDetector
from bgp_analyzer.detectors.route_leak import RouteLeakDetector
from bgp_analyzer.detectors.subprefix import SubprefixHijackDetector
from bgp_analyzer.parsers import load_routes

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class DetectorConfig:
    origin_hijack:    bool = True
    subprefix_hijack: bool = True
    route_leak:       bool = True
    bogon:            bool = True
    path_anomaly:     bool = True
    min_severity:     str  = "low"   # "low" | "medium" | "high"


@dataclass
class AnalysisResult:
    baseline_prefixes:      int          = 0
    baseline_routes:        int          = 0
    current_routes_scanned: int          = 0
    alerts:                 list[Alert]  = field(default_factory=list)

    @property
    def alert_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.kind] = counts.get(alert.kind, 0) + 1
        return counts

    @property
    def by_severity(self) -> dict[str, list[Alert]]:
        out: dict[str, list[Alert]] = {
            "high": [], "medium": [], "low": [], "info": []
        }
        for alert in self.alerts:
            out.setdefault(alert.severity, []).append(alert)
        return out


class BGPHijackAnalyzer:

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config    = config or DetectorConfig()
        self.detectors = self._build_detectors()

    def _build_detectors(self) -> list[BaseDetector]:
        cfg = self.config
        return [d for flag, d in [
            (cfg.origin_hijack,    OriginHijackDetector()),
            (cfg.subprefix_hijack, SubprefixHijackDetector()),
            (cfg.route_leak,       RouteLeakDetector()),
            (cfg.bogon,            BogonDetector()),
            (cfg.path_anomaly,     PathAnomalyDetector()),
        ] if flag]

    def build_baseline(self, path: str | Path) -> Baseline:
        return Baseline.build(load_routes(path))

    def analyze(
        self,
        baseline: Baseline,
        current_path: str | Path,
        progress_cb: Optional[Callable[[int], None]] = None,
    ) -> AnalysisResult:
        result = AnalysisResult(
            baseline_prefixes=baseline.total_prefixes,
            baseline_routes=baseline.total_routes,
        )

        min_rank = _SEVERITY_RANK.get(self.config.min_severity, 2)
        seen: set[tuple] = set()

        for route in load_routes(current_path):
            result.current_routes_scanned += 1
            if progress_cb and result.current_routes_scanned % 10_000 == 0:
                progress_cb(result.current_routes_scanned)

            for detector in self.detectors:
                for alert in detector.check(route, baseline):
                    if _SEVERITY_RANK.get(alert.severity, 3) > min_rank:
                        continue
                    key = (
                        alert.kind,
                        str(alert.prefix),
                        alert.current_route.origin_as if alert.current_route else None,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    result.alerts.append(alert)

        result.alerts.sort(key=lambda a: _SEVERITY_RANK.get(a.severity, 3))
        return result
