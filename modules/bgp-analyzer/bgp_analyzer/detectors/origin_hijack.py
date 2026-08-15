"""
Origin hijack detector.

Fires when a prefix is announced with an origin AS that was never
observed for that exact prefix in the baseline.

Severity scale:
  high   — the prefix has 1-2 stable baseline origins and the new AS
           is not among them; highest confidence of a genuine hijack.
  medium — the prefix has historically had many different origins
           (multi-homed or anycast prefix) so the new AS is suspicious
           but not definitive.
  low    — baseline has no origin information for this prefix
           (incomplete baseline data).
"""

from __future__ import annotations

from typing import Iterator

from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route
from bgp_analyzer.detectors.base import BaseDetector


class OriginHijackDetector(BaseDetector):

    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        if route.origin_as is None:
            return

        profile = baseline.get_profile(route.prefix)
        if profile is None:
            return  # unknown prefix — let subprefix detector handle it

        if route.origin_as in profile.origin_ases:
            return  # known origin

        known_count = len(profile.origin_ases)

        if known_count == 0:
            severity = "low"
            detail   = "baseline has no recorded origin AS"
        elif known_count <= 2:
            severity = "high"
            known_str = ", ".join(f"AS{a}" for a in sorted(profile.origin_ases))
            detail    = f"baseline origins: {known_str}"
        else:
            severity  = "medium"
            sample    = sorted(profile.origin_ases)[:5]
            known_str = ", ".join(f"AS{a}" for a in sample)
            detail    = f"baseline has {known_count} known origins including {known_str}..."

        yield Alert(
            kind="origin_hijack",
            severity=severity,
            prefix=route.prefix,
            description=(
                f"{route.prefix} announced by unexpected AS{route.origin_as} — {detail}"
            ),
            current_route=route,
            baseline_routes=profile.sample_routes,
            extra={
                "new_origin": route.origin_as,
                "known_origins": sorted(profile.origin_ases),
            },
        )
