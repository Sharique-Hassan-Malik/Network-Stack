"""`net` — one command across the six modules in this repository.

    net modules                          what is here and how to run each alone
    net congestion --loss 0.01           compare Reno, CUBIC and BBR on one link
    net bench https://example.com        -> http-benchmark
    net map 192.0.2.0/24                 -> topology-mapper
    net bgp updates.mrt                  -> bgp-analyzer

`bench`, `map` and `bgp` delegate to the module's own CLI rather than
reimplementing it — the same code path you get by running that module from its
own folder.
"""

from __future__ import annotations

import argparse
import importlib
import sys

from . import registry
from .measure import Report
from .simulate import Link, compare


def _cmd_modules(args: argparse.Namespace) -> int:
    print()
    for spec in registry.specs():
        absent = registry.missing_requirements(spec)
        state = "ready" if not absent else f"needs {', '.join(absent)}"
        print(f"  {spec.name:18} {state}")
        print(f"  {'':18} {spec.title}")
        for line in _wrap(spec.summary, 76):
            print(f"  {'':18} {line}")
        print(f"  {'':18} cd modules/{spec.name} && {spec.standalone}")
        print()
    return 0


def _cmd_congestion(args: argparse.Namespace) -> int:
    link = Link(
        bandwidth_bps=args.bandwidth * 1e6,
        base_rtt=args.rtt / 1000.0,
        queue_bytes=args.queue * 1024,
        loss_rate=args.loss,
    )
    run = compare(
        algorithms=tuple(args.algorithms),
        link=link,
        rounds=args.rounds,
        seed=args.seed,
    )

    print(f"\n  {run.target}, queue {args.queue} kB, loss {args.loss:.2%}, "
          f"{args.rounds} round trips\n")
    print(f"  {'algorithm':<10} {'throughput':>12} {'mean RTT':>10} "
          f"{'utilisation':>12} {'final cwnd':>12}")
    print(f"  {'-' * 60}")
    for algorithm, facts in run.facts.items():
        print(f"  {algorithm:<10} {facts['throughput_mbps']:>8.2f} Mb/s "
              f"{facts['mean_rtt_ms']:>8.1f} ms {facts['link_utilisation']:>11.0%} "
              f"{facts['final_cwnd_bytes']:>12,}")
    print()
    print("  A model of one bottleneck, not a network: no competing flow, no")
    print("  reordering, time in whole round trips. It separates the algorithms;")
    print("  it does not predict your link.\n")

    if args.json:
        report = Report(title="congestion comparison")
        report.add(run)
        if args.json == "-":
            print(report.to_json())
        else:
            from pathlib import Path

            Path(args.json).write_text(report.to_json(), encoding="utf-8")
            print(f"  JSON → {args.json}\n")
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, line = text.split(), [], []
    for word in words:
        if sum(len(w) + 1 for w in line) + len(word) > width and line:
            lines.append(" ".join(line))
            line = []
        line.append(word)
    if line:
        lines.append(" ".join(line))
    return lines


DELEGATED = {
    "bench": ("http-benchmark", "scripts.run_benchmark"),
    "map": ("topology-mapper", "map"),
    "bgp": ("bgp-analyzer", "bgp_analyzer.cli"),
}


def _delegate(command: str, argv: list[str]) -> int:
    module, entry = DELEGATED[command]
    registry.add_to_path(module)
    cli = importlib.import_module(entry)
    main = getattr(cli, "main", None)
    if main is None:
        print(f"net: {module} has no main() to delegate to", file=sys.stderr)
        return 2
    return int(main(argv) or 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net",
        description="Transports, analysers and the core they share.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("modules", help="the six modules and their own CLIs")

    congestion = sub.add_parser(
        "congestion", help="compare congestion controllers on one bottleneck"
    )
    congestion.add_argument("--algorithms", nargs="+", default=["reno", "cubic", "bbr"])
    congestion.add_argument("--bandwidth", type=float, default=10.0, metavar="MBPS")
    congestion.add_argument("--rtt", type=float, default=50.0, metavar="MS")
    congestion.add_argument("--queue", type=int, default=64, metavar="KB")
    congestion.add_argument("--loss", type=float, default=0.0, metavar="RATE")
    congestion.add_argument("--rounds", type=int, default=400)
    congestion.add_argument("--seed", type=int, default=0)
    congestion.add_argument("--json", metavar="FILE", nargs="?", const="-")

    for name, help_text in (("bench", "HTTP/1.1 vs /2 vs /3 benchmark"),
                            ("map", "map a network"),
                            ("bgp", "analyse BGP updates")):
        sub.add_parser(name, help=help_text, add_help=False)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Delegated subcommands are dispatched before argparse sees them, so their
    # flags — including --help — reach the module's own parser untouched.
    if argv and argv[0] in DELEGATED:
        return _delegate(argv[0], argv[1:])

    args = build_parser().parse_args(argv)
    if args.command == "modules":
        return _cmd_modules(args)
    return _cmd_congestion(args)


if __name__ == "__main__":
    raise SystemExit(main())
