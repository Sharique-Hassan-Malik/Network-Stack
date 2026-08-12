"""Tests for HNSWIndex."""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pytest

from vecdb.index.hnsw import HNSWIndex


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_index(metric: str = "cosine", M: int = 8, ef: int = 50) -> HNSWIndex:
    return HNSWIndex(dim=16, metric=metric, M=M, ef_construction=ef, ef_search=ef, seed=0)


def _unit(v: np.ndarray) -> np.ndarray:
    return (v / np.linalg.norm(v)).astype(np.float32)


# ---------------------------------------------------------------------------
# Construction and validation
# ---------------------------------------------------------------------------

def test_empty_index_len():
    idx = _make_index()
    assert len(idx) == 0


def test_invalid_dim():
    with pytest.raises(ValueError):
        HNSWIndex(dim=0, metric="cosine")


def test_invalid_M():
    with pytest.raises(ValueError):
        HNSWIndex(dim=4, metric="cosine", M=1)


def test_invalid_ef_construction():
    with pytest.raises(ValueError):
        HNSWIndex(dim=4, metric="cosine", M=8, ef_construction=4)


def test_wrong_dim_add():
    idx = HNSWIndex(dim=4, metric="cosine")
    with pytest.raises(ValueError):
        idx.add(np.ones(5, dtype=np.float32))


def test_2d_vector_rejected():
    idx = HNSWIndex(dim=4, metric="cosine")
    with pytest.raises(ValueError):
        idx.add(np.ones((2, 2), dtype=np.float32))


# ---------------------------------------------------------------------------
# Insert and basic search
# ---------------------------------------------------------------------------

def test_single_insert_search():
    idx = HNSWIndex(dim=4, metric="cosine", M=4, ef_construction=20, ef_search=10, seed=1)
    v = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    nid = idx.add(v, metadata={"tag": "x"})
    assert nid == 0
    assert len(idx) == 1
    results = idx.search(v, k=1)
    assert len(results) == 1
    dist, rid, meta = results[0]
    assert rid == 0
    assert dist == pytest.approx(0.0, abs=1e-5)
    assert meta == {"tag": "x"}


def test_search_returns_at_most_k():
    idx = _make_index()
    rng = np.random.default_rng(1)
    for i in range(10):
        idx.add(rng.standard_normal(16).astype(np.float32))
    results = idx.search(rng.standard_normal(16).astype(np.float32), k=5)
    assert len(results) <= 5


def test_search_empty_index():
    idx = _make_index()
    results = idx.search(np.ones(16, dtype=np.float32), k=5)
    assert results == []


def test_nearest_is_correct_cosine():
    """Insert 50 random unit vectors; query one of them exactly."""
    idx = HNSWIndex(dim=32, metric="cosine", M=8, ef_construction=100, ef_search=50, seed=7)
    rng = np.random.default_rng(7)
    vecs = rng.standard_normal((50, 32)).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
    for v in vecs:
        idx.add(v)
    results = idx.search(vecs[5], k=1)
    assert results[0][1] == 5


def test_nearest_is_correct_euclidean():
    idx = HNSWIndex(dim=16, metric="euclidean", M=8, ef_construction=80, ef_search=40, seed=3)
    rng = np.random.default_rng(3)
    vecs = rng.standard_normal((30, 16)).astype(np.float32)
    for v in vecs:
        idx.add(v)
    results = idx.search(vecs[12], k=1)
    assert results[0][1] == 12


def test_nearest_is_correct_dot():
    idx = HNSWIndex(dim=16, metric="dot", M=8, ef_construction=80, ef_search=40, seed=5)
    rng = np.random.default_rng(5)
    vecs = rng.standard_normal((30, 16)).astype(np.float32)
    for v in vecs:
        idx.add(v)
    results = idx.search(vecs[20], k=1)
    assert results[0][1] == 20


def test_results_sorted_ascending():
    idx = _make_index(M=8, ef=100)
    rng = np.random.default_rng(9)
    for _ in range(40):
        idx.add(rng.standard_normal(16).astype(np.float32))
    q = rng.standard_normal(16).astype(np.float32)
    results = idx.search(q, k=10, ef=50)
    dists = [d for d, _, _ in results]
    assert dists == sorted(dists)


def test_metadata_round_trip():
    idx = _make_index()
    meta = {"source": "wiki", "page": 42}
    idx.add(np.ones(16, dtype=np.float32), metadata=meta)
    results = idx.search(np.ones(16, dtype=np.float32), k=1)
    assert results[0][2] == meta


def test_metadata_none():
    idx = _make_index()
    idx.add(np.ones(16, dtype=np.float32))
    results = idx.search(np.ones(16, dtype=np.float32), k=1)
    assert results[0][2] is None


# ---------------------------------------------------------------------------
# Recall (quality)
# ---------------------------------------------------------------------------

def test_recall_cosine():
    """Recall@10 on 1000 random unit vectors should be > 0.85."""
    rng = np.random.default_rng(42)
    n, dim = 1_000, 64
    vecs = rng.standard_normal((n, dim)).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)

    idx = HNSWIndex(dim=dim, metric="cosine", M=16, ef_construction=200, ef_search=50, seed=42)
    for v in vecs:
        idx.add(v)

    k, n_q = 10, 50
    queries = vecs[:n_q]
    hits = 0
    for q in queries:
        from vecdb.distance.metrics import cosine as cos_fn
        dists = [cos_fn(q, vecs[i]) for i in range(n)]
        true_knn = set(np.argsort(dists)[:k])
        found = {nid for _, nid, _ in idx.search(q, k=k, ef=100)}
        hits += len(found & true_knn)
    recall = hits / (n_q * k)
    assert recall > 0.85, f"recall = {recall:.3f}"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_save_load_roundtrip():
    idx = _make_index()
    rng = np.random.default_rng(11)
    vecs = [rng.standard_normal(16).astype(np.float32) for _ in range(20)]
    for v in vecs:
        idx.add(v)

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "idx.pkl"
        idx.save(p)
        idx2 = HNSWIndex.load(p)

    assert len(idx2) == 20
    q = vecs[0]
    r1 = [(nid, round(d, 5)) for d, nid, _ in idx.search(q, k=5)]
    r2 = [(nid, round(d, 5)) for d, nid, _ in idx2.search(q, k=5)]
    assert r1 == r2


def test_load_wrong_type(tmp_path):
    import pickle
    p = tmp_path / "bad.pkl"
    with open(p, "wb") as fh:
        pickle.dump({"not": "an index"}, fh)
    with pytest.raises(TypeError):
        HNSWIndex.load(p)
