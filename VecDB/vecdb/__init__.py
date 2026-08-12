"""
vecdb — vector similarity search engine with HNSW indexing.

Supports cosine, dot-product and Euclidean distance metrics.
"""

__version__ = "1.0.0"

from .index.hnsw import HNSWIndex
from .distance.metrics import cosine, dot, euclidean, DistanceMetric
from .core.collection import Collection

__all__ = [
    "HNSWIndex",
    "cosine",
    "dot",
    "euclidean",
    "DistanceMetric",
    "Collection",
]
