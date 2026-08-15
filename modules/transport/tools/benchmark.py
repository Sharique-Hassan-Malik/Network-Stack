#!/usr/bin/env python3
"""
Benchmark: CTP/BBR vs CTP/CUBIC vs TCP

Measurements
------------
  Throughput  — send 20 MB over loopback and measure achieved MB/s.
  Latency     — 500 synchronous ping-pong round trips, report mean / P50 / P99.

Both endpoints run in separate processes to avoid GIL contention.

Usage
-----
    python tools/benchmark.py
    python tools/benchmark.py --size 50 --pings 1000
"""

import argparse
import multiprocessing as mp
import socket
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctp import CTPSocket

_BASE_PORT = 19200


# ── CTP helpers ────────────────────────────────────────────────────────────────

def _ctp_bulk_server(port: int, cc: str, ready: mp.Event, done: mp.Event) -> None:
    srv = CTPSocket(congestion=cc)
    srv.bind(("127.0.0.1", port))
    ready.set()
    conn, _ = srv.accept()
    total = 0
    while True:
        data = conn.recv(1 << 16, timeout=15)
        if not data:
            break
        total += len(data)
    conn.close()
    done.set()


def _ctp_bulk_client(port: int, cc: str, size_bytes: int, result: mp.Queue) -> None:
    time.sleep(0.05)   # brief pause for server to be ready
    sock = CTPSocket(congestion=cc)
    sock.connect(("127.0.0.1", port))
    payload = b"X" * (1 << 16)
    sent    = 0
    t0      = time.monotonic()
    while sent < size_bytes:
        chunk = min(len(payload), size_bytes - sent)
        sock.send(payload[:chunk])
        sent += chunk
    sock.close()
    elapsed = time.monotonic() - t0
    result.put(sent / elapsed / 1e6)   # MB/s


def _ctp_latency_server(port: int, cc: str, pings: int, ready: mp.Event) -> None:
    srv = CTPSocket(congestion=cc)
    srv.bind(("127.0.0.1", port))
    ready.set()
    conn, _ = srv.accept()
    for _ in range(pings):
        data = conn.recv(1, timeout=10)
        if not data:
            break
        conn.send(data)
    conn.close()


def _ctp_latency_client(port: int, cc: str, pings: int, result: mp.Queue) -> None:
    time.sleep(0.05)
    sock = CTPSocket(congestion=cc)
    sock.connect(("127.0.0.1", port))
    samples = []
    for _ in range(pings):
        t0 = time.monotonic()
        sock.send(b"\x00")
        sock.recv(1, timeout=5)
        samples.append((time.monotonic() - t0) * 1000)
    sock.close()
    result.put(samples)


# ── TCP helpers ────────────────────────────────────────────────────────────────

def _tcp_bulk_server(port: int, ready: mp.Event, done: mp.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.settimeout(15)
    try:
        while True:
            data = conn.recv(1 << 16)
            if not data:
                break
    except socket.timeout:
        pass
    conn.close()
    srv.close()
    done.set()


def _tcp_bulk_client(port: int, size_bytes: int, result: mp.Queue) -> None:
    time.sleep(0.05)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", port))
    payload = b"X" * (1 << 16)
    sent    = 0
    t0      = time.monotonic()
    while sent < size_bytes:
        chunk = min(len(payload), size_bytes - sent)
        sock.send(payload[:chunk])
        sent += chunk
    sock.close()
    elapsed = time.monotonic() - t0
    result.put(sent / elapsed / 1e6)


def _tcp_latency_server(port: int, pings: int, ready: mp.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.settimeout(10)
    try:
        for _ in range(pings):
            data = conn.recv(1)
            if not data:
                break
            conn.send(data)
    except socket.timeout:
        pass
    conn.close()
    srv.close()


def _tcp_latency_client(port: int, pings: int, result: mp.Queue) -> None:
    time.sleep(0.05)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", port))
    samples = []
    for _ in range(pings):
        t0 = time.monotonic()
        sock.send(b"\x00")
        sock.recv(1)
        samples.append((time.monotonic() - t0) * 1000)
    sock.close()
    result.put(samples)


# ── runner utilities ───────────────────────────────────────────────────────────

def _run_ctp_bulk(cc: str, size_mb: int, port: int) -> float:
    size    = size_mb * 1_000_000
    ready   = mp.Event()
    done    = mp.Event()
    result  = mp.Queue()

    srv = mp.Process(target=_ctp_bulk_server, args=(port, cc, ready, done), daemon=True)
    cli = mp.Process(target=_ctp_bulk_client, args=(port, cc, size, result),  daemon=True)

    srv.start()
    ready.wait(timeout=5)
    cli.start()
    cli.join(timeout=120)
    done.wait(timeout=10)
    srv.terminate()
    return result.get(timeout=2)


def _run_tcp_bulk(size_mb: int, port: int) -> float:
    size   = size_mb * 1_000_000
    ready  = mp.Event()
    done   = mp.Event()
    result = mp.Queue()

    srv = mp.Process(target=_tcp_bulk_server, args=(port, ready, done), daemon=True)
    cli = mp.Process(target=_tcp_bulk_client, args=(port, size, result),  daemon=True)

    srv.start()
    ready.wait(timeout=5)
    cli.start()
    cli.join(timeout=120)
    done.wait(timeout=10)
    srv.terminate()
    return result.get(timeout=2)


def _run_ctp_latency(cc: str, pings: int, port: int) -> list[float]:
    ready  = mp.Event()
    result = mp.Queue()

    srv = mp.Process(target=_ctp_latency_server, args=(port, cc, pings, ready), daemon=True)
    cli = mp.Process(target=_ctp_latency_client, args=(port, cc, pings, result),  daemon=True)

    srv.start()
    ready.wait(timeout=5)
    cli.start()
    cli.join(timeout=120)
    srv.terminate()
    return result.get(timeout=2)


def _run_tcp_latency(pings: int, port: int) -> list[float]:
    ready  = mp.Event()
    result = mp.Queue()

    srv = mp.Process(target=_tcp_latency_server, args=(port, pings, ready), daemon=True)
    cli = mp.Process(target=_tcp_latency_client, args=(port, pings, result),  daemon=True)

    srv.start()
    ready.wait(timeout=5)
    cli.start()
    cli.join(timeout=60)
    srv.terminate()
    return result.get(timeout=2)


def _fmt_latency(samples: list[float]) -> str:
    s = sorted(samples)
    n = len(s)
    mean = statistics.mean(s)
    p50  = s[n // 2]
    p99  = s[int(n * 0.99)]
    return f"mean {mean:.3f} ms   P50 {p50:.3f} ms   P99 {p99:.3f} ms"


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="CTP vs TCP benchmark")
    ap.add_argument("--size",  type=int, default=20,  help="Bulk transfer size in MB")
    ap.add_argument("--pings", type=int, default=500, help="Ping-pong iterations")
    args = ap.parse_args()

    print("=" * 64)
    print(f"  Custom Transport Protocol — Benchmark")
    print(f"  Bulk transfer: {args.size} MB   Latency pings: {args.pings}")
    print("=" * 64)

    col  = "{:<18} {:>14} {:>12}"
    sep  = "-" * 64

    # ── throughput ─────────────────────────────────────────────────────────────
    print("\n[ Bulk Throughput ]")
    print(col.format("Protocol", "Throughput", ""))
    print(sep)

    configs = [
        ("CTP / BBR",   lambda: _run_ctp_bulk("bbr",   args.size, _BASE_PORT)),
        ("CTP / CUBIC", lambda: _run_ctp_bulk("cubic", args.size, _BASE_PORT + 1)),
        ("TCP",         lambda: _run_tcp_bulk(args.size,           _BASE_PORT + 2)),
    ]

    throughputs: dict[str, float] = {}
    for name, fn in configs:
        print(f"  {name} ...", end=" ", flush=True)
        try:
            mbps = fn()
            throughputs[name] = mbps
            print(f"{mbps:>8.2f} MB/s")
        except Exception as exc:
            print(f"ERROR: {exc}")

    # ── latency ────────────────────────────────────────────────────────────────
    print("\n[ Ping-Pong Latency ]")
    lat_configs = [
        ("CTP / BBR",   lambda: _run_ctp_latency("bbr",   args.pings, _BASE_PORT + 3)),
        ("CTP / CUBIC", lambda: _run_ctp_latency("cubic", args.pings, _BASE_PORT + 4)),
        ("TCP",         lambda: _run_tcp_latency(args.pings,           _BASE_PORT + 5)),
    ]

    for name, fn in lat_configs:
        print(f"  {name} ...", end=" ", flush=True)
        try:
            samples = fn()
            print(f"  {_fmt_latency(samples)}")
        except Exception as exc:
            print(f"ERROR: {exc}")

    # ── summary ────────────────────────────────────────────────────────────────
    if "TCP" in throughputs and throughputs["TCP"] > 0:
        print("\n[ Relative Throughput (TCP = 100 %) ]")
        tcp_bw = throughputs["TCP"]
        for name, bw in throughputs.items():
            pct = 100 * bw / tcp_bw
            bar = "█" * int(pct / 5)
            print(f"  {name:<18} {bar:<22} {pct:6.1f} %")

    print()


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
