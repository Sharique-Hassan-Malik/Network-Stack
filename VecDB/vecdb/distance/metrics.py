"""
Distance and similarity metrics used by the index.

All functions accept two 1-D numpy arrays of the same length and return
a non-negative scalar where smaller means closer (for use in a min-heap).

cosine    — 1 − cosine_similarity     ∈ [0, 2]
dot       — −(a · b)                  (negated so smaller = more similar)
euclidean — ||a − b||₂                ∈ [0, ∞)
"""

from __future__ import annotations

from enum import Enum
from typing import Callable

import numpy as np


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    """1 − cosine similarity. Range [0, 2]; 0 = identical direction."""
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0.0:
        return 0.0
    return float(max(0.0, 1.0 - np.dot(a, b) / denom))


def dot(a: np.ndarray, b: np.ndarray) -> float:
    """Negated dot product. Smaller = more similar (higher original dot)."""
    return float(-np.dot(a, b))


def euclidean(a: np.ndarray, b: np.ndarray) -> float:
    """Euclidean (L2) distance."""
    return float(np.linalg.norm(a - b))


# Registry used by HNSWIndex and Collection to look up metrics by name.
_REGISTRY: dict[str, Callable[[np.ndarray, np.ndarray], float]] = {
    "cosine":    cosine,
    "dot":       dot,
    "euclidean": euclidean,
}


class DistanceMetric(str, Enum):
    """Enum of supported distance metrics."""
    COSINE    = "cosine"
    DOT       = "dot"
    EUCLIDEAN = "euclidean"


def get(name: str) -> Callable[[np.ndarray, np.ndarray], float]:
    """Return the metric function for *name*, raising KeyError if unknown."""
    try:
        return _REGISTRY[name.lower()]
    except KeyError:
        raise KeyError(f"Unknown metric '{name}'. Valid choices: {list(_REGISTRY)}")
