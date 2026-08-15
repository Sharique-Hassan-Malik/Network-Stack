"""
Route leak detector.

A route leak occurs when an AS re-advertises a route beyond its intended
scope — typically a customer re-advertising provider routes to another
provider, or a peer forwarding routes it should only propagate to its
own customers.

Without a full AS relationship database two heuristics are applied:

1. Path length increase
   If the current AS path for a known prefix is significantly longer
   than the average baseline path length, extra ASes have inserted
   themselves as transit hops, which is a symptom of a route leak.

2. Unexpected Tier-1 transit
   A Tier-1 AS appearing between two non-Tier-1 ASes that was never
   seen in that position for this prefix in the baseline suggests that
   a Tier-1 provider is incorrectly transiting a route that should not
   leave a lower-tier network.

Both checks only fire for prefixes with baseline data.
"""

from __future__ import annotations

from typing import Iterator

from bgp_analyzer.core.asinfo import TIER1_ASNS
from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route
from bgp_analyzer.detectors.base import BaseDetector

PATH_LEN_EXCESS = 3   # hops above baseline average that triggers the alert


class RouteLeakDetector(BaseDetector):

    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        if route.as_path is None:
            return

        profile = baseline.get_profile(route.prefix)
        if profile is None:
            return

        current_len  = route.as_path.length
        baseline_avg = profile.avg_path_length

        if baseline_avg > 0 and current_len >= baseline_avg + PATH_LEN_EXCESS:
            yield Alert(
                kind="route_leak",
                severity="medium",
                prefix=route.prefix,
                description=(
                    f"{route.prefix} path length {current_len} is "
                    f"{current_len - baseline_avg:.1f} hops above "
                    f"baseline average of {baseline_avg:.1f}"
                ),
                current_route=route,
                baseline_routes=profile.sample_routes,
                extra={
                    "current_path_len": current_len,
                    "baseline_avg_len": round(baseline_avg, 2),
                    "excess_hops": round(current_len - baseline_avg, 1),
                },
            )
            return  # one alert per route

        # Check 2: unexpected Tier-1 transit
        asns = route.as_path.all_asns
        for i in range(1, len(asns) - 1):
            asn      = asns[i]
            prev_asn = asns[i - 1]
            next_asn = asns[i + 1]
            if (
                asn in TIER1_ASNS
                and prev_asn not in TIER1_ASNS
                and next_asn not in TIER1_ASNS
                and not any(str(asn) in path for path in profile.as_paths)
            ):
                yield Alert(
                    kind="route_leak",
                    severity="medium",
                    prefix=route.prefix,
                    description=(
                        f"{route.prefix} path contains unexpected Tier-1 "
                        f"transit AS{asn} between AS{prev_asn} and AS{next_asn}"
                    ),
                    current_route=route,
                    baseline_routes=profile.sample_routes,
                    extra={
                        "transit_as": asn,
                        "neighbors": [prev_asn, next_asn],
                    },
                )
                return
