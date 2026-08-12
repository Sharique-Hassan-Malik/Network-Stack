"""
Analysis and comparison of scenario results across protocols.

Groups results by scenario, computes relative speedups and formats
console-friendly tables.
"""

from __future__ import annotations

from collections import defaultdict

from benchmark.metrics import ScenarioResult


def group_by_scenario(results: list[ScenarioResult]) -> dict[str, list[ScenarioResult]]:
    """Group ScenarioResult objects by their scenario name."""
    groups: dict[str, list[ScenarioResult]] = defaultdict(list)
    for r in results:
        groups[r.scenario].append(r)
    return dict(groups)


def speedup_table(results: list[ScenarioResult]) -> list[dict]:
    """
    For each scenario, compute H2 and H3 speedup relative to H1 on wall time.
    Returns a list of dicts suitable for JSON or tabular display.
    """
    rows = []
    for scenario, group in group_by_scenario(results).items():
        by_proto = {r.protocol: r for r in group}
        h1 = by_proto.get("HTTP/1.1")
        if not h1:
            continue
        row = {
            "scenario":          scenario,
            "h1_wall_ms":        round(h1.wall_time * 1000, 1),
            "h1_latency_p50_ms": round(h1.latency_p50 * 1000, 2),
            "h1_rps":            round(h1.rps, 1),
        }
        for proto_key, col in [("HTTP/2", "h2"), ("HTTP/3", "h3")]:
            r = by_proto.get(proto_key)
            if r and r.wall_time > 0:
                speedup = h1.wall_time / r.wall_time
                row[f"{col}_wall_ms"]        = round(r.wall_time * 1000, 1)
                row[f"{col}_latency_p50_ms"] = round(r.latency_p50 * 1000, 2)
                row[f"{col}_rps"]            = round(r.rps, 1)
                row[f"{col}_speedup"]        = round(speedup, 2)
            else:
                row[f"{col}_wall_ms"]        = None
                row[f"{col}_latency_p50_ms"] = None
                row[f"{col}_rps"]            = None
                row[f"{col}_speedup"]        = None
        rows.append(row)
    return rows


def print_summary(results: list[ScenarioResult]) -> None:
    """Print a formatted summary table to stdout."""
    groups = group_by_scenario(results)
    col = 18

    print(f"\n{'='*76}")
    print("  HTTP/1.1 vs HTTP/2 vs HTTP/3 — Benchmark Results")
    print(f"{'='*76}")

    for scenario, group in groups.items():
        print(f"\n  Scenario: {scenario}")
        print(f"  {'Protocol':<14} {'Wall ms':>9} {'RPS':>8} {'TTFB p50':>10} {'p50':>9} {'p95':>9} {'p99':>9} {'Errors':>7}")
        print(f"  {'-'*76}")
        by_proto = {"HTTP/1.1": None, "HTTP/2": None, "HTTP/3": None}
        for r in group:
            by_proto[r.protocol] = r

        baseline_wall = None
        for proto in ("HTTP/1.1", "HTTP/2", "HTTP/3"):
            r = by_proto.get(proto)
            if not r:
                continue
            if baseline_wall is None:
                baseline_wall = r.wall_time

            speedup = ""
            if baseline_wall and r.wall_time > 0 and proto != "HTTP/1.1":
                sp = baseline_wall / r.wall_time
                speedup = f"  ×{sp:.2f}"

            err_str = f"{r.errors}" if r.errors else "—"
            print(
                f"  {proto:<14}"
                f" {r.wall_time*1000:>8.1f}"
                f" {r.rps:>8.1f}"
                f" {r.ttfb_p50*1000:>9.2f}"
                f" {r.latency_p50*1000:>8.2f}"
                f" {r.latency_p95*1000:>8.2f}"
                f" {r.latency_p99*1000:>8.2f}"
                f" {err_str:>7}"
                f"{speedup}"
            )

    print(f"\n{'='*76}")
    print("  Columns: Wall ms = total elapsed  |  RPS = requests/sec  |  "
          "TTFB/p50/p95/p99 in ms")
    print(f"{'='*76}\n")


def results_to_json(results: list[ScenarioResult]) -> list[dict]:
    """Serialise all results to a JSON-safe list of dicts."""
    return [r.to_dict() for r in results]
