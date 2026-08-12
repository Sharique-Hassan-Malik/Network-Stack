"""
Command-line interface for vecdb.

Commands
--------
  bench    — run the HNSW benchmark and print a report
  demo     — interactive demo: insert random vectors and query them
"""

from __future__ import annotations

import argparse
import sys

import numpy as np


def _cmd_bench(args: argparse.Namespace) -> None:
    from vecdb.benchmark.runner import run
    report = run(
        n=args.n,
        dim=args.dim,
        metric=args.metric,
        M=args.M,
        ef_construction=args.ef_construction,
        ef_search=args.ef_search,
        k=args.k,
        n_queries=args.queries,
        seed=args.seed,
    )
    print(report)


def _cmd_demo(args: argparse.Namespace) -> None:
    from vecdb import Collection

    rng = np.random.default_rng(0)
    col = Collection("demo", dim=args.dim, metric=args.metric)

    print(f"Inserting {args.n} random {args.dim}-d vectors ...")
    vecs = rng.standard_normal((args.n, args.dim)).astype(np.float32)
    keys = [f"vec:{i}" for i in range(args.n)]
    col.add_batch(keys, vecs)
    print(f"Index size: {len(col)}")

    q = rng.standard_normal(args.dim).astype(np.float32)
    print(f"\nQuerying for k={args.k} nearest neighbours ...")
    results = col.query(q, k=args.k)
    for r in results:
        print(f"  {r['key']:<12}  dist={r['distance']:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="vecdb", description="Vector database CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    bp = sub.add_parser("bench", help="Run HNSW benchmark")
    bp.add_argument("--n",               type=int,   default=10_000)
    bp.add_argument("--dim",             type=int,   default=128)
    bp.add_argument("--metric",          default="cosine")
    bp.add_argument("--M",               type=int,   default=16)
    bp.add_argument("--ef-construction", dest="ef_construction", type=int, default=200)
    bp.add_argument("--ef-search",       dest="ef_search",       type=int, default=50)
    bp.add_argument("--k",               type=int,   default=10)
    bp.add_argument("--queries",         type=int,   default=200)
    bp.add_argument("--seed",            type=int,   default=42)
    bp.set_defaults(func=_cmd_bench)

    dp = sub.add_parser("demo", help="Interactive demo")
    dp.add_argument("--n",      type=int, default=5_000)
    dp.add_argument("--dim",    type=int, default=64)
    dp.add_argument("--metric", default="cosine")
    dp.add_argument("--k",      type=int, default=10)
    dp.set_defaults(func=_cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
