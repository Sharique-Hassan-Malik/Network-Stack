"""Tests for Collection — high-level vector store."""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pytest

from vecdb.core.collection import Collection


def _col(metric: str = "cosine") -> Collection:
    return Collection("test", dim=16, metric=metric, M=8,
                      ef_construction=80, ef_search=40, seed=0)


def _vecs(n: int, dim: int = 16, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    v = rng.standard_normal((n, dim)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True)
    return v


# ---------------------------------------------------------------------------
# upsert / len / contains
# ---------------------------------------------------------------------------

def test_empty_collection():
    col = _col()
    assert len(col) == 0


def test_upsert_single():
    col = _col()
    col.upsert("a", np.ones(16, dtype=np.float32))
    assert len(col) == 1
    assert "a" in col


def test_upsert_duplicate_ignored():
    col = _col()
    v1 = np.ones(16, dtype=np.float32)
    v2 = np.zeros(16, dtype=np.float32)
    col.upsert("a", v1)
    col.upsert("a", v2)
    assert len(col) == 1


def test_key_not_present():
    col = _col()
    assert "missing" not in col


def test_add_batch_size():
    col = _col()
    vecs = _vecs(20)
    keys = [f"k:{i}" for i in range(20)]
    col.add_batch(keys, vecs)
    assert len(col) == 20


def test_add_batch_shape_mismatch():
    col = _col()
    with pytest.raises(ValueError):
        col.add_batch(["a"], np.ones((1, 8), dtype=np.float32))


def test_add_batch_key_count_mismatch():
    col = _col()
    with pytest.raises(ValueError):
        col.add_batch(["a", "b"], np.ones((3, 16), dtype=np.float32))


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

def test_get_existing():
    col = _col()
    v = np.ones(16, dtype=np.float32)
    col.upsert("x", v, metadata={"src": "test"})
    result = col.get("x")
    assert result is not None
    assert result["key"] == "x"
    assert result["metadata"] == {"src": "test"}
    np.testing.assert_array_almost_equal(result["vector"], v)


def test_get_missing_returns_none():
    col = _col()
    assert col.get("ghost") is None


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

def test_query_returns_k_results():
    col = _col()
    vecs = _vecs(30)
    for i, v in enumerate(vecs):
        col.upsert(f"v{i}", v)
    q = vecs[0]
    results = col.query(q, k=5)
    assert len(results) == 5


def test_query_result_structure():
    col = _col()
    col.upsert("doc1", np.ones(16, dtype=np.float32), metadata=42)
    results = col.query(np.ones(16, dtype=np.float32), k=1)
    r = results[0]
    assert "key"      in r
    assert "distance" in r
    assert "metadata" in r


def test_query_nearest_key():
    col = _col()
    rng = np.random.default_rng(3)
    vecs = rng.standard_normal((50, 16)).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
    for i, v in enumerate(vecs):
        col.upsert(f"v{i}", v)
    target_idx = 17
    results = col.query(vecs[target_idx], k=1)
    assert results[0]["key"] == f"v{target_idx}"


def test_query_distances_non_negative_cosine():
    col = _col(metric="cosine")
    vecs = _vecs(20)
    for i, v in enumerate(vecs):
        col.upsert(f"v{i}", v)
    results = col.query(vecs[0], k=10)
    for r in results:
        assert r["distance"] >= 0.0


def test_query_distances_non_negative_euclidean():
    col = _col(metric="euclidean")
    vecs = _vecs(20)
    for i, v in enumerate(vecs):
        col.upsert(f"v{i}", v)
    results = col.query(vecs[0], k=10)
    for r in results:
        assert r["distance"] >= 0.0


def test_query_sorted_ascending():
    col = _col()
    vecs = _vecs(40)
    for i, v in enumerate(vecs):
        col.upsert(f"v{i}", v)
    results = col.query(vecs[5], k=10)
    dists = [r["distance"] for r in results]
    assert dists == sorted(dists)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_save_load_roundtrip():
    col = _col()
    vecs = _vecs(25)
    for i, v in enumerate(vecs):
        col.upsert(f"key:{i}", v, metadata={"i": i})

    with tempfile.TemporaryDirectory() as tmp:
        col.save(tmp)
        col2 = Collection.load(tmp)

    assert col2.name   == col.name
    assert col2.dim    == col.dim
    assert col2.metric == col.metric
    assert len(col2)   == len(col)
    for i in range(25):
        assert f"key:{i}" in col2


def test_load_preserves_query_results():
    col = _col()
    vecs = _vecs(30)
    for i, v in enumerate(vecs):
        col.upsert(f"k{i}", v)

    with tempfile.TemporaryDirectory() as tmp:
        col.save(tmp)
        col2 = Collection.load(tmp)

    q = vecs[10]
    r1 = [x["key"] for x in col.query(q,  k=5)]
    r2 = [x["key"] for x in col2.query(q, k=5)]
    assert r1 == r2


def test_save_creates_required_files():
    col = _col()
    col.upsert("a", np.ones(16, dtype=np.float32))
    with tempfile.TemporaryDirectory() as tmp:
        col.save(tmp)
        p = Path(tmp)
        assert (p / "meta.json").exists()
        assert (p / "index.pkl").exists()
