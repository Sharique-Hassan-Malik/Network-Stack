"""
Benchmark utilities for measuring HNSW index quality and speed.

Metrics
-------
recall@k  — fraction of true k-NN found in the index's k results.
            Computed against exact brute-force search over the same dataset.
qps       — queries per second at a given ef value.
build_s   — seconds to insert all vectors.

Usage
-----
    from vecdb.benchmark.runner import run
    report = run(n=10_000, dim=128, metric="cosine", k=10, ef=50)
    print(report)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ..index.hnsw import HNSWIndex
from ..distance.metrics import get as get_metric


@dataclass
class BenchmarkReport:
    n:             int
    dim:           int
    metric:        str
    M:             int
    ef_construction: int
    ef_search:     int
    k:             int
    recall:        float
    build_s:       float
    qps:           float
    n_queries:     int

    def __str__(self) -> str:
        lines = [
            "HNSW Benchmark",
            f"  vectors       : {self.n:,}",
            f"  dim           : {self.dim}",
            f"  metric        : {self.metric}",
            f"  M             : {self.M}",
            f"  ef_construction: {self.ef_construction}",
            f"  ef_search     : {self.ef_search}",
            f"  k             : {self.k}",
            f"  recall@{self.k:<2}     : {self.recall:.4f}",
            f"  build time    : {self.build_s:.2f}s",
            f"  QPS           : {self.qps:,.0f}",
            f"  queries       : {self.n_queries}",
        ]
        return "\n".join(lines)


def _brute_force_knn(
    dataset: np.ndarray,
    queries: np.ndarray,
    k: int,
    dist_fn,
) -> list[set[int]]:
    """Return the true k-NN sets for each query using exact search."""
    true_nn: list[set[int]] = []
    for q in queries:
        dists = np.array([dist_fn(q, dataset[i]) for i in range(len(dataset))])
        top_k = set(int(i) for i in np.argpartition(dists, k)[:k])
        true_nn.append(top_k)
    return true_nn


def run(
    n: int = 10_000,
    dim: int = 128,
    metric: str = "cosine",
    M: int = 16,
    ef_construction: int = 200,
    ef_search: int = 50,
    k: int = 10,
    n_queries: int = 200,
    seed: int = 42,
) -> BenchmarkReport:
    """
    Build an HNSW index on *n* random vectors and measure recall and QPS.

    Parameters
    ----------
    n:                Number of vectors to index.
    dim:              Vector dimensionality.
    metric:           Distance metric.
    M, ef_construction, ef_search: HNSW hyperparameters.
    k:                Nearest-neighbour count.
    n_queries:        Number of query vectors for recall and QPS measurement.
    seed:             NumPy RNG seed.
    """
    rng = np.random.default_rng(seed)
    dataset = rng.standard_normal((n, dim)).astype(np.float32)
    if metric == "cosine":
        norms = np.linalg.norm(dataset, axis=1, keepdims=True)
        dataset /= np.clip(norms, 1e-9, None)
    queries = rng.standard_normal((n_queries, dim)).astype(np.float32)
    if metric == "cosine":
        qnorms = np.linalg.norm(queries, axis=1, keepdims=True)
        queries /= np.clip(qnorms, 1e-9, None)

    dist_fn = get_metric(metric)

    # Build
    index = HNSWIndex(dim=dim, metric=metric, M=M,
                      ef_construction=ef_construction, ef_search=ef_search, seed=seed)
    t0 = time.perf_counter()
    for vec in dataset:
        index.add(vec)
    build_s = time.perf_counter() - t0

    # Ground truth (on the n_queries subset only to keep wall-time reasonable)
    true_nn = _brute_force_knn(dataset, queries, k, dist_fn)

    # Recall
    hits = 0
    for i, q in enumerate(queries):
        results = index.search(q, k=k, ef=ef_search)
        found = {nid for _, nid, _ in results}
        hits += len(found & true_nn[i])
    recall = hits / (n_queries * k)

    # QPS
    t1 = time.perf_counter()
    for q in queries:
        index.search(q, k=k, ef=ef_search)
    elapsed = time.perf_counter() - t1
    qps = n_queries / elapsed

    return BenchmarkReport(
        n=n, dim=dim, metric=metric, M=M,
        ef_construction=ef_construction, ef_search=ef_search,
        k=k, recall=recall, build_s=build_s, qps=qps, n_queries=n_queries,
    )
