from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.core.types import Alert, Route


class BaseDetector(ABC):

    @abstractmethod
    def check(self, route: Route, baseline: Baseline) -> Iterator[Alert]:
        """Yield zero or more Alerts for a single Route against the baseline."""
        ...
