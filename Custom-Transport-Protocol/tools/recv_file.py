#!/usr/bin/env python3
"""
Receive a file over CTP and write it to disk.

Example
-------
    python tools/recv_file.py --port 9000 --output received.bin
"""

import argparse
import sys
import time
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctp import CTPSocket


def _fmt_rate(bps: float) -> str:
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} GB/s"
    if bps >= 1e6:
        return f"{bps / 1e6:.2f} MB/s"
    if bps >= 1e3:
        return f"{bps / 1e3:.2f} KB/s"
    return f"{bps:.0f} B/s"


def receive(host: str, port: int, output: Path, congestion: str, chunk: int) -> None:
    sock = CTPSocket(congestion=congestion)
    sock.bind((host, port))
    print(f"Listening on {host}:{port}  [{congestion.upper()}]")

    conn, addr = sock.accept()
    print(f"Connection from {addr[0]}:{addr[1]}")

    total    = 0
    t_start  = time.monotonic()
    t_report = t_start
    buf      = bytearray()

    try:
        while True:
            data = conn.recv(chunk, timeout=10.0)
            if not data:
                break
            buf   += data
            total += len(data)
            now    = time.monotonic()
            if now - t_report >= 1.0:
                elapsed = now - t_start
                rate    = total / elapsed if elapsed > 0 else 0
                print(f"  Received {total / 1e6:.2f} MB — {_fmt_rate(rate)}", end="\r")
                t_report = now
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()

    elapsed = time.monotonic() - t_start
    rate    = total / elapsed if elapsed > 0 else 0
    print(f"\nDone. {total / 1e6:.3f} MB in {elapsed:.2f}s — {_fmt_rate(rate)}")

    output.write_bytes(bytes(buf))
    print(f"Saved → {output}")


def main() -> None:
    p = argparse.ArgumentParser(description="CTP file receiver")
    p.add_argument("--host",       default="0.0.0.0",   help="Bind address")
    p.add_argument("--port",       type=int, required=True)
    p.add_argument("--output",     type=Path, required=True)
    p.add_argument("--congestion", default="bbr", choices=["bbr", "cubic"])
    p.add_argument("--chunk",      type=int, default=65536, help="recv() buffer size")
    args = p.parse_args()
    receive(args.host, args.port, args.output, args.congestion, args.chunk)


if __name__ == "__main__":
    main()
