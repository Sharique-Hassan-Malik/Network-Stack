#!/usr/bin/env python3
"""
Send a file over CTP to a waiting receiver.

Example
-------
    python tools/send_file.py --host 127.0.0.1 --port 9000 --file mydata.bin
"""

import argparse
import sys
import time
from pathlib import Path

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


def send(host: str, port: int, filepath: Path, congestion: str, chunk: int) -> None:
    data = filepath.read_bytes()
    size = len(data)
    print(f"Sending {filepath.name}  ({size / 1e6:.3f} MB)  [{congestion.upper()}]")

    sock = CTPSocket(congestion=congestion)
    sock.connect((host, port))
    print(f"Connected to {host}:{port}")

    t_start = time.monotonic()
    offset  = 0

    try:
        while offset < size:
            end   = min(offset + chunk, size)
            sent  = sock.send(data[offset:end])
            offset += sent

            elapsed = time.monotonic() - t_start
            pct     = 100 * offset / size
            rate    = offset / elapsed if elapsed > 0 else 0
            bar     = "#" * int(pct / 2)
            print(f"  [{bar:<50}] {pct:5.1f}%  {_fmt_rate(rate)}", end="\r")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    elapsed = time.monotonic() - t_start
    rate    = size / elapsed if elapsed > 0 else 0
    print(f"\nDone. {size / 1e6:.3f} MB in {elapsed:.2f}s — {_fmt_rate(rate)}")


def main() -> None:
    p = argparse.ArgumentParser(description="CTP file sender")
    p.add_argument("--host",       required=True)
    p.add_argument("--port",       type=int, required=True)
    p.add_argument("--file",       type=Path, required=True)
    p.add_argument("--congestion", default="bbr", choices=["bbr", "cubic"])
    p.add_argument("--chunk",      type=int, default=65536, help="send() chunk size")
    args = p.parse_args()

    if not args.file.exists():
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    send(args.host, args.port, args.file, args.congestion, args.chunk)


if __name__ == "__main__":
    main()
