"""
AS path anomaly detector.

Detects two categories:

path_loop    — the same AS number appears more than once in the path.
               BGP loop prevention should make this impossible in
               well-behaved implementations; its presence indicates
               misconfiguration or crafted packets.

path_anomaly — a private AS number (64512–65534 or 4200000000–4294967294)
               appears in a path that is propagating in the global routing
               table.  Private ASNs should be stripped before announcement
               to any external peer.
"""

from __future__ import annotations

from typing import Iterator

from bgp_analyzer.core.asinfo import is_private_asn
from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route
from bgp_analyzer.detectors.base import BaseDetector


class PathAnomalyDetector(BaseDetector):

    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        if route.as_path is None:
            return

        # AS path loop
        if route.as_path.has_loop():
            asns = route.as_path.all_asns
            seen: set[int] = set()
            duplicates: list[int] = []
            for asn in asns:
                if asn in seen and asn not in duplicates:
                    duplicates.append(asn)
                seen.add(asn)

            yield Alert(
                kind="path_loop",
                severity="medium",
                prefix=route.prefix,
                description=(
                    f"{route.prefix} AS path contains loop — "
                    f"repeated: {', '.join(f'AS{a}' for a in duplicates[:5])}"
                ),
                current_route=route,
                extra={
                    "repeated_ases": duplicates[:10],
                    "full_path": route.path_str,
                },
            )

        # Private AS leaking into global table
        private = [a for a in route.as_path.all_asns if is_private_asn(a)]
        if private:
            yield Alert(
                kind="path_anomaly",
                severity="low",
                prefix=route.prefix,
                description=(
                    f"{route.prefix} AS path contains private ASN(s): "
                    f"{', '.join(f'AS{a}' for a in private[:5])}"
                ),
                current_route=route,
                extra={
                    "private_asns": private[:10],
                    "full_path": route.path_str,
                },
            )
