#!/usr/bin/env python3
"""
Demonstrate stream multiplexing: open N streams simultaneously and send
different payloads on each.  Shows QUIC's key advantage over HTTP/1.1 —
streams share a single UDP flow but are independent at the application layer
(no head-of-line blocking at the transport level).

Usage
-----
  python tools/multiplex_demo.py
  python tools/multiplex_demo.py --streams 5 --payload 32768
"""

import argparse
import multiprocessing as mp
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quic.connection import QUICConnection

_PORT = 14433


def _server(ready: mp.Event, n_streams: int) -> None:
    srv = QUICConnection(is_server=True)
    srv.bind(("127.0.0.1", _PORT))
    ready.set()
    conn = srv.accept()

    received: dict[int, bytearray] = {}
    threads = []

    for sid in range(0, n_streams * 4, 4):   # bidi stream IDs for client: 0,4,8…
        def _reader(stream_id=sid):
            rs  = conn.recv_stream(stream_id)
            buf = bytearray()
            while True:
                chunk = rs.read(65536, timeout=10.0)
                if not chunk:
                    break
                buf += chunk
                if rs.is_fin_read():
                    break
            received[stream_id] = buf
        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=15)

    conn.close()
    srv.close()

    total = sum(len(v) for v in received.values())
    print(f"[server] received {len(received)} streams, {total} bytes total")
    for sid, buf in sorted(received.items()):
        print(f"  stream {sid:3d}: {len(buf):>8,} bytes  "
              f"checksum={sum(buf) % 65536:#06x}")


def _client(n_streams: int, payload_size: int) -> None:
    conn = QUICConnection(is_server=False)
    conn.connect(("127.0.0.1", _PORT))

    streams = [conn.open_stream() for _ in range(n_streams)]
    t0      = time.monotonic()

    def _writer(stream, sid):
        data = bytes((sid * 7 + i) % 256 for i in range(payload_size))
        chunk = 4096
        for off in range(0, len(data), chunk):
            stream.write(data[off: off + chunk])
        stream.close()

    threads = [
        threading.Thread(target=_writer, args=(s, i), daemon=True)
        for i, s in enumerate(streams)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    time.sleep(1.5)   # let data flush
    conn.close()

    elapsed = time.monotonic() - t0
    total   = n_streams * payload_size
    print(f"[client] sent {n_streams} streams × {payload_size:,} bytes = {total:,} bytes")
    print(f"         elapsed {elapsed:.2f}s  throughput {total/elapsed/1e6:.2f} MB/s")


def main() -> None:
    ap = argparse.ArgumentParser(description="QUIC stream multiplexing demo")
    ap.add_argument("--streams", type=int, default=4,     help="Number of concurrent streams")
    ap.add_argument("--payload", type=int, default=16384, help="Bytes per stream")
    args = ap.parse_args()

    ready  = mp.Event()
    server = mp.Process(target=_server, args=(ready, args.streams), daemon=True)
    server.start()
    ready.wait(timeout=5)

    _client(args.streams, args.payload)

    server.join(timeout=10)
    server.terminate()


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
