"""Command line: resolve a name from the root and show the walk.

    python tools/resolve.py example.com
    python tools/resolve.py --type MX iana.org
    python tools/resolve.py --trace www.github.com
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnskit import ResolveError, Resolver, wire  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Resolve a name iteratively, starting at the root servers.")
    ap.add_argument("name")
    ap.add_argument("--type", "-t", default="A",
                    help="record type: A, AAAA, NS, MX, TXT, SOA, CNAME")
    ap.add_argument("--trace", action="store_true",
                    help="show every server consulted on the way down")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args(argv)

    qtype = wire.NAME_TYPES.get(args.type.upper())
    if qtype is None:
        print(f"unknown record type {args.type!r}; "
              f"known: {', '.join(sorted(wire.NAME_TYPES))}", file=sys.stderr)
        return 2

    resolver = Resolver(timeout=args.timeout)
    try:
        answer = resolver.resolve(args.name, qtype)
    except ResolveError as exc:
        print(f"resolution failed: {exc}", file=sys.stderr)
        return 1

    if args.trace:
        print()
        for step in answer.trace:
            print(f"  {step}")
        print()

    if answer.rcode != wire.RCODE_NOERROR:
        print(f"  {answer.name}  {answer.rcode_name if hasattr(answer, 'rcode_name') else wire.RCODE_NAMES.get(answer.rcode, answer.rcode)}")
    elif not answer.records:
        print(f"  {answer.name}  NOERROR, no {args.type.upper()} record")
    else:
        for record in answer.records:
            print(f"  {record}")

    print()
    print(f"  {answer.queries_sent} quer{'y' if answer.queries_sent == 1 else 'ies'} "
          f"in {answer.elapsed * 1000:.0f} ms"
          f"{', from cache' if answer.from_cache else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
