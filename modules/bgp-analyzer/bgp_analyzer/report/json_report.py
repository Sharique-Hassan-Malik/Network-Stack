"""
JSON report serializer.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bgp_analyzer.analyzer import AnalysisResult


def to_dict(result: "AnalysisResult") -> dict:
    return {
        "generated": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "summary": {
            "baseline_prefixes":      result.baseline_prefixes,
            "baseline_routes":        result.baseline_routes,
            "current_routes_scanned": result.current_routes_scanned,
            "total_alerts":           len(result.alerts),
            "alert_counts":           result.alert_counts,
        },
        "alerts": [a.to_dict() for a in result.alerts],
    }


def to_json(result: "AnalysisResult", indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def save(result: "AnalysisResult", path: str | Path) -> None:
    Path(path).write_text(to_json(result), encoding="utf-8")
