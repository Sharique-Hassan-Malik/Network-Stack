"""
Sub-prefix hijack detector.

Fires when a more specific prefix is announced by an AS that does not
originate any covering prefix in the baseline.  Sub-prefix hijacks are
the most common BGP attack because BGP's longest-prefix-match rule
causes traffic to be pulled toward the more specific announcement.

Example:
  Baseline: 1.0.0.0/8   originated by AS13335
  Current:  1.0.4.0/22  originated by AS666  ← sub-prefix hijack

The detector first checks whether the announcing AS legitimately
disaggregates any covering prefix.  If it does, the route is clean.

Severity scale:
  high   — host route (/32 IPv4 or /128 IPv6) or covering prefix has
           a single stable origin.
  medium — otherwise.
"""

from __future__ import annotations

from typing import Iterator

from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route
from bgp_analyzer.detectors.base import BaseDetector


class SubprefixHijackDetector(BaseDetector):

    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        if route.origin_as is None:
            return

        if baseline.has_prefix(route.prefix):
            return  # exact match handled by origin hijack detector

        covering = baseline.covering_prefixes(route.prefix)
        if not covering:
            return  # no covering prefix in baseline — cannot make a judgment

        # If this AS originates any covering prefix legitimately, allow it
        for cov_prefix in covering:
            cov_profile = baseline.get_profile(cov_prefix)
            if cov_profile and route.origin_as in cov_profile.origin_ases:
                return

        # All covering prefixes are owned by different ASes
        best_cover  = max(covering, key=lambda p: p.prefixlen)
        cov_profile = baseline.get_profile(best_cover)
        known_origins = sorted(cov_profile.origin_ases) if cov_profile else []

        max_len  = 32 if route.prefix.version == 4 else 128
        severity = "high" if (
            route.prefix.prefixlen == max_len
            or (cov_profile and len(cov_profile.origin_ases) == 1)
        ) else "medium"

        known_str = ", ".join(f"AS{a}" for a in known_origins[:5]) or "unknown"
        yield Alert(
            kind="subprefix_hijack",
            severity=severity,
            prefix=route.prefix,
            description=(
                f"More-specific {route.prefix} announced by AS{route.origin_as} — "
                f"covering prefix {best_cover} belongs to {known_str}"
            ),
            current_route=route,
            baseline_routes=cov_profile.sample_routes if cov_profile else [],
            extra={
                "covering_prefix": str(best_cover),
                "covering_origins": known_origins,
                "announcing_as": route.origin_as,
            },
        )
