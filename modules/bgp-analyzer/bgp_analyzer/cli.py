"""
BGP Hijack Analyzer — command-line interface.

Usage examples:

  # Build baseline from historical MRT dump, scan current dump
  bgp-analyzer baseline.mrt current.mrt

  # Accept bgpdump -m text files as well
  bgp-analyzer baseline.txt.gz current.txt.gz

  # Save JSON report
  bgp-analyzer baseline.mrt current.mrt --json report.json

  # Only report high-severity findings
  bgp-analyzer baseline.mrt current.mrt --min-severity high

  # Enable only specific detectors
  bgp-analyzer baseline.mrt current.mrt --disable route_leak --disable path_anomaly

  # Run a self-contained demo without any real data files
  bgp-analyzer --demo

  # Show baseline statistics then exit
  bgp-analyzer --baseline-stats baseline.mrt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from bgp_analyzer import __version__
from bgp_analyzer.analyzer import BGPHijackAnalyzer, DetectorConfig
from bgp_analyzer.core.baseline import Baseline
from bgp_analyzer.report import render, save

console = Console()

_ALL_DETECTORS = {
    "origin_hijack",
    "subprefix_hijack",
    "route_leak",
    "bogon",
    "path_anomaly",
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bgp-analyzer",
        description="Detect BGP hijacks, sub-prefix hijacks and route leaks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"bgp-analyzer {__version__}")

    # Positional
    p.add_argument(
        "baseline",
        nargs="?",
        metavar="BASELINE",
        help="Historical MRT binary or bgpdump text file used to build the baseline.",
    )
    p.add_argument(
        "current",
        nargs="?",
        metavar="CURRENT",
        help="Current MRT binary or bgpdump text file to scan for anomalies.",
    )

    # Modes
    p.add_argument(
        "--demo",
        action="store_true",
        help="Run self-contained demo with synthetic data.",
    )
    p.add_argument(
        "--baseline-stats",
        metavar="FILE",
        help="Print baseline statistics for FILE and exit.",
    )

    # Filters
    p.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity to report (default: low).",
    )
    p.add_argument(
        "--disable",
        metavar="DETECTOR",
        action="append",
        default=[],
        choices=sorted(_ALL_DETECTORS),
        dest="disabled",
        help="Disable a detector. Repeatable.",
    )

    # Output
    p.add_argument(
        "--json",
        metavar="FILE",
        help="Write JSON report to FILE in addition to terminal output.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress terminal output (useful with --json).",
    )

    return p


def _make_config(args: argparse.Namespace) -> DetectorConfig:
    disabled = set(args.disabled)
    return DetectorConfig(
        origin_hijack=    "origin_hijack"    not in disabled,
        subprefix_hijack= "subprefix_hijack" not in disabled,
        route_leak=       "route_leak"       not in disabled,
        bogon=            "bogon"            not in disabled,
        path_anomaly=     "path_anomaly"     not in disabled,
        min_severity=     args.min_severity,
    )


def _run_demo(config: DetectorConfig, args: argparse.Namespace) -> int:
    from bgp_analyzer.core.baseline import Baseline
    from bgp_analyzer.generator import baseline_routes, current_routes_attacked

    console.print("[bold blue]Running demo with synthetic attack scenarios…[/bold blue]\n")
    baseline = Baseline.build(baseline_routes())
    analyzer = BGPHijackAnalyzer(config)

    # Temporarily replace load_routes path with generator
    from bgp_analyzer import analyzer as _mod
    _orig = _mod.load_routes

    def _fake_load(_path):
        return current_routes_attacked()

    _mod.load_routes = _fake_load
    try:
        result = analyzer.analyze(baseline, Path("/dev/null"))
    finally:
        _mod.load_routes = _orig

    if not args.quiet:
        render(result)
    if args.json:
        save(result, args.json)
        console.print(f"\nJSON report written to [bold]{args.json}[/bold]")
    return 0


def _run_baseline_stats(path: str) -> int:
    from bgp_analyzer.parsers import load_routes

    console.print(f"[bold blue]Building baseline from {path}…[/bold blue]")
    baseline = Baseline.build(load_routes(path))

    console.print(f"  Prefixes : [bold]{baseline.total_prefixes:,}[/bold]")
    console.print(f"  Routes   : [bold]{baseline.total_routes:,}[/bold]")

    # Top 10 prefixes by route count
    from rich.table import Table
    from rich import box

    profiles = sorted(
        baseline.iter_profiles(), key=lambda p: p.route_count, reverse=True
    )[:10]

    tbl = Table(title="Top 10 prefixes by route count", box=box.SIMPLE_HEAD)
    tbl.add_column("Prefix",       width=22)
    tbl.add_column("Routes",       justify="right", width=8)
    tbl.add_column("Origins",      width=30)
    tbl.add_column("Avg path len", justify="right", width=12)

    for prof in profiles:
        tbl.add_row(
            str(prof.prefix),
            str(prof.route_count),
            " ".join(f"AS{a}" for a in sorted(prof.origin_ases)[:6]),
            f"{prof.avg_path_length:.1f}",
        )
    console.print(tbl)
    return 0


def _progress(n: int) -> None:
    console.print(f"  Scanned {n:,} routes…", end="\r")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)
    config = _make_config(args)

    if args.demo:
        return _run_demo(config, args)

    if args.baseline_stats:
        return _run_baseline_stats(args.baseline_stats)

    if not args.baseline or not args.current:
        parser.print_help()
        return 1

    if not Path(args.baseline).exists():
        console.print(f"[red]Baseline file not found: {args.baseline}[/red]")
        return 2

    if not Path(args.current).exists():
        console.print(f"[red]Current file not found: {args.current}[/red]")
        return 2

    console.print(f"[bold blue]Building baseline from {args.baseline}…[/bold blue]")
    baseline = Baseline.build(__import__("bgp_analyzer.parsers", fromlist=["load_routes"]).load_routes(args.baseline))
    console.print(f"  {baseline.total_prefixes:,} prefixes  {baseline.total_routes:,} routes")

    console.print(f"\n[bold blue]Scanning {args.current}…[/bold blue]")
    analyzer = BGPHijackAnalyzer(config)
    result   = analyzer.analyze(
        baseline,
        args.current,
        progress_cb=None if args.quiet else _progress,
    )
    if not args.quiet:
        console.print()
        render(result)

    if args.json:
        save(result, args.json)
        if not args.quiet:
            console.print(f"\nJSON report written to [bold]{args.json}[/bold]")

    high = len(result.by_severity["high"])
    return 0 if high == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
