"""Tests for distance metric functions."""

from __future__ import annotations

import math

import numpy as np
import pytest

from vecdb.distance.metrics import cosine, dot, euclidean, get, DistanceMetric


def test_cosine_identical():
    a = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    assert cosine(a, a) == pytest.approx(0.0, abs=1e-6)


def test_cosine_orthogonal():
    a = np.array([1.0, 0.0], dtype=np.float32)
    b = np.array([0.0, 1.0], dtype=np.float32)
    assert cosine(a, b) == pytest.approx(1.0, abs=1e-6)


def test_cosine_opposite():
    a = np.array([1.0, 0.0], dtype=np.float32)
    b = np.array([-1.0, 0.0], dtype=np.float32)
    assert cosine(a, b) == pytest.approx(2.0, abs=1e-6)


def test_cosine_zero_vector():
    z = np.zeros(3, dtype=np.float32)
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    assert cosine(z, a) == pytest.approx(0.0)


def test_dot_positive():
    a = np.array([1.0, 2.0], dtype=np.float32)
    b = np.array([3.0, 4.0], dtype=np.float32)
    assert dot(a, b) == pytest.approx(-11.0)


def test_dot_symmetry():
    rng = np.random.default_rng(0)
    a = rng.standard_normal(16).astype(np.float32)
    b = rng.standard_normal(16).astype(np.float32)
    assert dot(a, b) == pytest.approx(dot(b, a))


def test_euclidean_same_point():
    a = np.array([3.0, 4.0], dtype=np.float32)
    assert euclidean(a, a) == pytest.approx(0.0)


def test_euclidean_known():
    a = np.array([0.0, 0.0], dtype=np.float32)
    b = np.array([3.0, 4.0], dtype=np.float32)
    assert euclidean(a, b) == pytest.approx(5.0)


def test_get_valid():
    for name in ("cosine", "dot", "euclidean"):
        fn = get(name)
        assert callable(fn)


def test_get_invalid():
    with pytest.raises(KeyError):
        get("manhattan")


def test_get_case_insensitive():
    fn = get("COSINE")
    assert fn is cosine


def test_metric_enum_values():
    assert DistanceMetric.COSINE.value    == "cosine"
    assert DistanceMetric.DOT.value       == "dot"
    assert DistanceMetric.EUCLIDEAN.value == "euclidean"
