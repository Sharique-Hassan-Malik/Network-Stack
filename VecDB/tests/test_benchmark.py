"""Tests for the benchmark runner."""

from __future__ import annotations

from vecdb.benchmark.runner import run, BenchmarkReport


def test_benchmark_returns_report():
    report = run(n=500, dim=16, metric="cosine", k=5, n_queries=20, seed=0)
    assert isinstance(report, BenchmarkReport)


def test_benchmark_recall_in_range():
    report = run(n=500, dim=16, metric="cosine", k=5, n_queries=20, seed=1)
    assert 0.0 <= report.recall <= 1.0


def test_benchmark_qps_positive():
    report = run(n=500, dim=16, metric="cosine", k=5, n_queries=20, seed=2)
    assert report.qps > 0.0


def test_benchmark_build_time_positive():
    report = run(n=200, dim=8, metric="euclidean", k=3, n_queries=10, seed=3)
    assert report.build_s > 0.0


def test_benchmark_str():
    report = run(n=200, dim=8, metric="cosine", k=3, n_queries=10, seed=4)
    s = str(report)
    assert "recall" in s.lower()
    assert "qps"    in s.lower()


def test_benchmark_dot_metric():
    report = run(n=300, dim=16, metric="dot", k=5, n_queries=15, seed=5)
    assert isinstance(report.recall, float)
