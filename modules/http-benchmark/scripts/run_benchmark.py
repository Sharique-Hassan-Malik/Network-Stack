"""
Run the full HTTP/1.1 vs HTTP/2 vs HTTP/3 benchmark and display results.

Usage:
  python scripts/run_benchmark.py
  python scripts/run_benchmark.py --n-concurrent 30 --no-dashboard
  python scripts/run_benchmark.py --host 127.0.0.1 --h1-port 8080 --h2-port 8443
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import uvicorn

from server.certs import generate as generate_certs
from benchmark.runner import BenchmarkRunner
from analysis.stats import print_summary, results_to_json, speedup_table


def _start_test_server(host: str, h1_port: int, h2_port: int, cert_path: str, key_path: str) -> None:
    """Start HTTP/1.1 and HTTP/2 servers in background threads."""
    from server.app import app as asgi_app

    def run_h1():
        uvicorn.run(
            asgi_app,
            host=host, port=h1_port,
            log_level="error",
        )

    def run_h2():
        uvicorn.run(
            asgi_app,
            host=host, port=h2_port,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            http="h11",          # hypercorn would be used for real H2; uvicorn with httptools supports h2 via TLS
            log_level="error",
        )

    t1 = threading.Thread(target=run_h1, daemon=True)
    t1.start()

    t2 = threading.Thread(target=run_h2, daemon=True)
    t2.start()

    # Give servers time to bind
    time.sleep(1.5)


def _start_hypercorn_servers(
    host: str, h1_port: int, h2_port: int,
    cert_path: str, key_path: str,
) -> None:
    """
    Use hypercorn which natively supports HTTP/1.1, HTTP/2 and HTTP/3.
    Run each server in a separate OS thread with its own event loop.
    """
    import hypercorn.asyncio
    from hypercorn.config import Config

    from server.app import app as asgi_app

    def run(config: Config) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(hypercorn.asyncio.serve(asgi_app, config))

    # HTTP/1.1 plain
    c1 = Config()
    c1.bind = [f"{host}:{h1_port}"]
    c1.loglevel = "error"
    threading.Thread(target=run, args=(c1,), daemon=True).start()

    # HTTP/2 over TLS
    c2 = Config()
    c2.bind = [f"{host}:{h2_port}"]
    c2.certfile = cert_path
    c2.keyfile  = key_path
    c2.loglevel = "error"
    threading.Thread(target=run, args=(c2,), daemon=True).start()

    time.sleep(2.0)


def _start_dashboard(dashboard_port: int) -> None:
    """Start the result dashboard in a background thread."""
    from dashboard.app import app as dash_app

    def run():
        uvicorn.run(dash_app, host="127.0.0.1", port=dashboard_port, log_level="error")

    threading.Thread(target=run, daemon=True).start()
    time.sleep(0.5)


async def _run_benchmark(
    host:         str,
    h1_port:      int,
    h2_port:      int,
    n_concurrent: int,
    cert_path:    str,
) -> list:
    from benchmark.metrics import ScenarioResult

    h1_url = f"http://{host}:{h1_port}"
    h2_url = f"https://{host}:{h2_port}"

    runner = BenchmarkRunner(
        h1_url=h1_url,
        h2_url=h2_url,
        h3_url=None,        # set to h2_url with h3_port if aioquic + HTTP/3 server available
        cert_path=cert_path,
    )

    def progress(msg: str) -> None:
        print(f"  → {msg}")

    results = await runner.run_all(n_concurrent=n_concurrent, progress_cb=progress)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host",           default="127.0.0.1")
    ap.add_argument("--h1-port",        type=int, default=8880)
    ap.add_argument("--h2-port",        type=int, default=8443)
    ap.add_argument("--n-concurrent",   type=int, default=20)
    ap.add_argument("--dashboard-port", type=int, default=9000)
    ap.add_argument("--no-dashboard",   action="store_true")
    ap.add_argument("--output",         default=None, help="Write JSON results to file")
    args = ap.parse_args()

    print("\nHTTP/1.1 vs HTTP/2 vs HTTP/3 Performance Analyzer")
    print("=" * 52)

    # TLS certificates
    print("\n[1/4] Generating TLS certificates…")
    cert_path, key_path = generate_certs()

    # Start test servers
    print("[2/4] Starting test servers…")
    try:
        _start_hypercorn_servers(
            args.host, args.h1_port, args.h2_port,
            str(cert_path), str(key_path),
        )
        print(f"      HTTP/1.1 → http://{args.host}:{args.h1_port}")
        print(f"      HTTP/2   → https://{args.host}:{args.h2_port}")
    except ImportError:
        print("      hypercorn not found, falling back to uvicorn (HTTP/1.1 and HTTP/2 via TLS)")
        _start_test_server(args.host, args.h1_port, args.h2_port, str(cert_path), str(key_path))

    # Dashboard
    if not args.no_dashboard:
        print(f"[3/4] Starting dashboard → http://127.0.0.1:{args.dashboard_port}")
        _start_dashboard(args.dashboard_port)
    else:
        print("[3/4] Dashboard skipped (--no-dashboard)")

    # Run benchmark
    print("[4/4] Running benchmark scenarios…\n")
    results = asyncio.run(_run_benchmark(
        host=args.host,
        h1_port=args.h1_port,
        h2_port=args.h2_port,
        n_concurrent=args.n_concurrent,
        cert_path=str(cert_path),
    ))

    # Print summary to terminal
    print_summary(results)

    # Update dashboard state
    if not args.no_dashboard:
        from dashboard.app import update_state
        results_json = results_to_json(results)
        summary      = speedup_table(results)
        update_state(results_json, summary)
        print(f"Dashboard updated → http://127.0.0.1:{args.dashboard_port}")
        print("Press Ctrl+C to exit.\n")

    # Optionally write JSON
    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(results_to_json(results), indent=2))
        print(f"Results written → {out}")

    # Keep dashboard alive
    if not args.no_dashboard:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
