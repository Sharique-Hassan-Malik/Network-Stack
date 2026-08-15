#!/usr/bin/env python3
"""
Transfer a file over QUIC streams.

Usage
-----
  # receiver
  python tools/transfer.py recv --port 4433 --output out.bin

  # sender
  python tools/transfer.py send --host 127.0.0.1 --port 4433 --file data.bin
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quic.connection import QUICConnection


def _fmt(bps: float) -> str:
    for unit, div in (("GB/s", 1e9), ("MB/s", 1e6), ("KB/s", 1e3)):
        if bps >= div:
            return f"{bps/div:.2f} {unit}"
    return f"{bps:.0f} B/s"


def cmd_recv(args: argparse.Namespace) -> None:
    srv = QUICConnection(is_server=True)
    srv.bind(("0.0.0.0", args.port))
    print(f"Listening on :{args.port}")

    conn = srv.accept()
    print(f"Connection established — receiving on stream 0")

    rs    = conn.recv_stream(0)
    buf   = bytearray()
    t0    = time.monotonic()

    while True:
        chunk = rs.read(65536, timeout=10.0)
        if not chunk:
            break
        buf += chunk
        if rs.is_fin_read():
            break

    elapsed = time.monotonic() - t0
    rate    = len(buf) / elapsed if elapsed > 0 else 0
    print(f"Received {len(buf)/1e6:.3f} MB in {elapsed:.2f}s — {_fmt(rate)}")
    conn.close()

    Path(args.output).write_bytes(bytes(buf))
    print(f"Saved → {args.output}")


def cmd_send(args: argparse.Namespace) -> None:
    data = Path(args.file).read_bytes()
    print(f"Sending {args.file}  ({len(data)/1e6:.3f} MB)")

    conn = QUICConnection(is_server=False)
    conn.connect((args.host, args.port))
    print("Handshake complete")

    stream = conn.open_stream()
    t0     = time.monotonic()

    chunk_size = 4096
    for off in range(0, len(data), chunk_size):
        stream.write(data[off: off + chunk_size])

    stream.close()

    # Wait for data to flush
    time.sleep(max(1.0, len(data) / 1_000_000))
    conn.close()

    elapsed = time.monotonic() - t0
    rate    = len(data) / elapsed if elapsed > 0 else 0
    print(f"Sent {len(data)/1e6:.3f} MB in {elapsed:.2f}s — {_fmt(rate)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="QUIC file transfer")
    sub = ap.add_subparsers(dest="cmd")

    rp = sub.add_parser("recv")
    rp.add_argument("--port",   type=int, required=True)
    rp.add_argument("--output", required=True)

    sp = sub.add_parser("send")
    sp.add_argument("--host", required=True)
    sp.add_argument("--port", type=int, required=True)
    sp.add_argument("--file", required=True)

    args = ap.parse_args()
    if args.cmd == "recv":
        cmd_recv(args)
    elif args.cmd == "send":
        cmd_send(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
