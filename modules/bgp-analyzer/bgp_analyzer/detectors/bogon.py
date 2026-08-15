"""
Bogon prefix and AS detector.

Fires on:
  bogon_prefix — the announced prefix overlaps a special-purpose or
                 unroutable range (RFC 1918, RFC 5735, RFC 6890, etc.)
  bogon_as     — the AS path contains a private, reserved or documentation
                 AS number that should never appear in the global table

Bogon AS numbers include the private ranges 64512–65534 and
4200000000–4294967294, the AS_TRANS placeholder 23456 and reserved
values 0 and 65535.
"""

from __future__ import annotations

from typing import Iterator

from bgp_analyzer.core.asinfo import bogon_asn_reason, is_bogon_asn, is_bogon_prefix
from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route
from bgp_analyzer.detectors.base import BaseDetector


class BogonDetector(BaseDetector):

    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        flag, matched_range = is_bogon_prefix(route.prefix)
        if flag:
            yield Alert(
                kind="bogon_prefix",
                severity="high",
                prefix=route.prefix,
                description=(
                    f"{route.prefix} is a bogon prefix (overlaps {matched_range}) "
                    f"announced by AS{route.origin_as}"
                ),
                current_route=route,
                extra={"bogon_range": matched_range},
            )

        if route.as_path is None:
            return

        for asn in route.as_path.all_asns:
            if is_bogon_asn(asn):
                yield Alert(
                    kind="bogon_as",
                    severity="medium",
                    prefix=route.prefix,
                    description=(
                        f"{route.prefix} path contains bogon AS{asn} "
                        f"({bogon_asn_reason(asn)})"
                    ),
                    current_route=route,
                    extra={
                        "bogon_asn": asn,
                        "reason": bogon_asn_reason(asn),
                        "full_path": route.path_str,
                    },
                )
                break  # one bogon-AS alert per route
