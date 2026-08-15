# Custom Transport Protocol

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; its RTT estimation and congestion control come from `netcore`.

A reliable transport protocol implemented over UDP in Python, featuring BBR and CUBIC
congestion control.  The project demonstrates how TCP-like reliability (sequencing,
ACKs, retransmission, flow control) is built from scratch, and replaces TCP's
loss-based AIMD with a model-based algorithm (BBR) that separates bandwidth estimation
from congestion response.

---

## The Hard Part

Building a reliable protocol on top of unreliable UDP requires solving several
interacting problems simultaneously:

**Sequence number wraparound** — 32-bit counters roll over at 2³² bytes.
All comparisons use half-space arithmetic (`seq_lt`, `seq_le` in `buffer.py`)
to correctly handle wraparound without special-casing.

**RTT estimation under loss** — Naively averaging RTT samples including
retransmits inflates the estimate.  Karn's algorithm (only sample non-retransmitted
segments) combined with Jacobson's EWMA prevents this.  Exponential backoff on
consecutive timeouts avoids flooding a congested path.

**BBR without kernel access** — BBR's pacing normally requires kernel-level
packet scheduling.  Here it is approximated in userspace with `time.sleep()` delays
between segments, which is accurate enough for benchmarking but adds CPU overhead
compared to a kernel implementation.

**Thread safety without overhead** — Three threads share transport state (send
window, receive buffer, congestion control).  Python's GIL makes integer reads
atomic, so only the containers that need ordered multi-step updates carry explicit
locks.  A `threading.Event` in `RecvBuffer` eliminates busy-waiting in `recv()`.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design: packet layout, state machine diagram,
threading model and file map.

---

## Packet Format

```
 ┌──────────────┬──────────────┬──────────┬──────────┬──────────────┐
 │  seq (4B)    │  ack (4B)    │ flags(1) │  win(2)  │  csum (2B)   │
 ├──────────────┴──────────────┴──────────┴──────────┴──────────────┤
 │  data_len (4B)              │  timestamp (8B)                     │
 ├─────────────────────────────┴─────────────────────────────────────┤
 │  payload (up to 1400 bytes)                                       │
 └───────────────────────────────────────────────────────────────────┘
```

Total overhead: 26 bytes per segment (vs TCP's minimum 20 bytes).

---

## Congestion Control

| Algorithm | Core idea | cwnd control |
|-----------|-----------|--------------|
| BBR | Estimate bottleneck BW and RTprop; pace at BtlBw | `cwnd_gain × BtlBw × RTprop` |
| CUBIC | Cubic window growth since last loss event | `C × (t − K)³ + W_max` |
| TCP (reference) | AIMD on loss | OS kernel |

BBR paces sends to match the estimated bottleneck rate, so it avoids building
large queues (bufferbloat).  CUBIC grows more aggressively in high-BDP paths
but reacts only after a loss occurs.

---

## Setup

```bash
python -m pip install -r requirements.txt
```

No third-party runtime dependencies.  Standard library only.  `pytest` is
required for tests.

---

## Running Tests

```bash
pytest tests/ -v
```

---

## File Transfer

```bash
# Terminal 1 — start receiver
python tools/recv_file.py --port 9000 --output received.bin

# Terminal 2 — send file
python tools/send_file.py --host 127.0.0.1 --port 9000 --file /path/to/file.bin
```

Use `--congestion cubic` to switch the algorithm on either side.

---

## Benchmark

```bash
python tools/benchmark.py
# or
python tools/benchmark.py --size 50 --pings 1000
```

Sample output on a local loopback:

```
================================================================
  Custom Transport Protocol — Benchmark
  Bulk transfer: 20 MB   Latency pings: 500
================================================================

[ Bulk Throughput ]
Protocol             Throughput
----------------------------------------------------------------
  CTP / BBR ...      112.34 MB/s
  CTP / CUBIC ...     98.76 MB/s
  TCP ...            234.50 MB/s

[ Ping-Pong Latency ]
  CTP / BBR ...    mean 0.142 ms   P50 0.138 ms   P99 0.451 ms
  CTP / CUBIC ...  mean 0.187 ms   P50 0.182 ms   P99 0.601 ms
  TCP ...          mean 0.108 ms   P50 0.105 ms   P99 0.312 ms

[ Relative Throughput (TCP = 100 %) ]
  CTP / BBR          ████████████████████         47.9 %
  CTP / CUBIC        █████████████████            42.1 %
  TCP                ████████████████████████████ 100.0 %
```

CTP's throughput gap vs TCP on loopback is expected: Python userspace pacing
adds `time.sleep()` overhead per segment that a kernel bypass would avoid.
On paths with non-trivial delay and competing traffic, BBR's queue-avoidance
advantage becomes visible.

---

## Usage as a Library

```python
from ctp import CTPSocket

# Receiver
srv = CTPSocket(congestion="bbr")
srv.bind(("0.0.0.0", 9000))
conn, addr = srv.accept()
data = conn.recv(1 << 20)
conn.close()

# Sender
cli = CTPSocket(congestion="bbr")
cli.connect(("127.0.0.1", 9000))
cli.send(b"hello")
cli.close()
```

---

## Relevant Coursework

This project applies concepts from:

- **Computer Communication and Networks** — transport layer design, sliding window protocols,
  connection state machines and flow control
- **Communication Systems** — bandwidth estimation, RTT measurement
- **Probability Methods in Engineering** — exponentially-weighted moving averages in
  the Jacobson RTT estimator (EWMA is a first-order IIR filter)
- **Signals and Systems** — the analogy between EWMA smoothing and a discrete-time
  low-pass filter

---

## References

- Jacobson, V. (1988). Congestion avoidance and control. *ACM SIGCOMM*.
- Cardwell, N. et al. (2016). BBR: Congestion-Based Congestion Control. *ACM Queue*.
- Ha, S. et al. (2008). CUBIC: a new TCP-friendly high-speed TCP variant. *ACM SIGOPS*.
- RFC 6298 — Computing TCP's Retransmission Timer.
- RFC 8312 — CUBIC for Fast and Long-Distance Networks.
