# Architecture

## Overview

Custom Transport Protocol (CTP) implements reliable, ordered, congestion-controlled
data delivery over UDP.  The design mirrors TCP's core mechanisms while replacing
the loss-based AIMD congestion control with BBR (Bottleneck Bandwidth and RTT)
as the default algorithm.

```
 Application
     │   send(data) / recv(n)
     ▼
 CTPSocket                       ← public API (ctp/socket.py)
     │
     ├── SendWindow              ← sliding send window (ctp/buffer.py)
     │     └── _Seg[]            ← per-segment: seq, data, sent_at, retries
     │
     ├── RecvBuffer              ← reorder + in-order delivery (ctp/buffer.py)
     │     └── _ooo{}            ← out-of-order hold buffer
     │
     ├── BBR / CUBIC             ← congestion control (ctp/congestion.py)
     │     └── cwnd, pacing_rate
     │
     ├── RTTEstimator            ← Jacobson/Karn SRTT + RTTVAR (ctp/rtt.py)
     │     └── rto
     │
     └── UDP socket              ← OS kernel UDP/IP
```

---

## Packet Format

```
 0               8              16              24              31
 ┌───────────────────────────────────────────────────────────────┐
 │                         seq_num (32)                          │
 ├───────────────────────────────────────────────────────────────┤
 │                         ack_num (32)                          │
 ├───────────┬───────────┬───────────────┬───────────────────────┤
 │ flags (8) │  rsv (8)  │  window (16)  │    checksum (16)      │
 ├───────────────────────────────────────┴───────────────────────┤
 │                        data_len (32)                          │
 ├───────────────────────────────────────────────────────────────┤
 │                       timestamp (64)                          │
 ├───────────────────────────────────────────────────────────────┤
 │                     payload (data_len)                        │
 └───────────────────────────────────────────────────────────────┘
```

Total header: 26 bytes.  Payload limited to 1400 bytes (MAX_SEGMENT_DATA)
to stay within typical MTU minus IP + UDP overhead.

Flag bits: `SYN=0x01  ACK=0x02  FIN=0x04  RST=0x08  DATA=0x10`

Checksum: CRC-32 of the entire packet (header with checksum field zeroed out
plus payload), truncated to the lower 16 bits.

---

## Connection State Machine

```
  CLOSED ──bind()──► LISTEN
                        │
                    accept()
                        │ SYN received
                        ▼
                   SYN_RECEIVED ──► ESTABLISHED ◄── connect()
                                        │               │
                              close()   │               │ SYN → SYN_SENT
                                        ▼               │
                                   FIN_WAIT_1           │ SYN-ACK received
                                        │               ▼
                                        ▼          ESTABLISHED
                                   FIN_WAIT_2
                                        │
                                        ▼
                                   TIME_WAIT ──► CLOSED

  Passive close path:
  ESTABLISHED ──FIN received──► CLOSE_WAIT ──► LAST_ACK ──ACK──► CLOSED
```

---

## Threading Model

After a connection is established, two background threads are created:

| Thread | Responsibility |
|--------|----------------|
| `ctp-io` | Reads UDP datagrams in a tight loop, parses packets, dispatches to `_dispatch()` |
| `ctp-rtx` | Polls every 10 ms, calls `SendWindow.timed_out(rto)`, retransmits and applies backoff |

The calling thread (application) drives `send()` and `recv()`.  `send()` paces
segments against the BBR pacing rate using `time.sleep()`.  `recv()` blocks on
`RecvBuffer.read()`, which uses a `threading.Event` to avoid busy-waiting.

Thread safety:
- `SendWindow` and `RecvBuffer` have internal `threading.Lock` instances.
- `cwnd` and `pacing_rate` are Python `int`/`float`, written only by the I/O
  thread and read by the send loop — GIL ensures atomic access.

---

## Congestion Control

### BBR

BBR maintains two estimates:

| Estimate | How measured |
|----------|-------------|
| `btl_bw` | Max delivery rate (bytes ACKed / elapsed) over a 10-round filter window |
| `rt_prop` | Running minimum RTT sample |

From these it derives:
- **pacing rate** = `pacing_gain × btl_bw`
- **cwnd** = `cwnd_gain × btl_bw × rt_prop` (bandwidth-delay product)

State cycle:
1. **STARTUP** — pacing gain 2.885, doubles estimated BW each RTT until three
   consecutive rounds show < 25 % growth.
2. **DRAIN** — gain < 1 to empty the queue built in STARTUP.
3. **PROBE_BW** — cycles through `[1.25, 0.75, 1.0 ×6]` each RTT to probe for
   extra bandwidth without building a persistent queue.
4. **PROBE_RTT** — reduces cwnd briefly every 10 seconds to get a clean RTprop
   sample.

### CUBIC

Window function: `W(t) = C × (t − K)³ + W_max`

- After a loss event, `W_max` is set to the current window, `ssthresh` is
  reduced by factor β = 0.7, and K is computed so the cubic reaches `W_max`
  at time K.
- Before loss, standard TCP slow start applies until `ssthresh`.

---

## Reliability Mechanisms

| Mechanism | Implementation |
|-----------|---------------|
| Sequence numbers | 32-bit byte offsets, wraparound with half-space comparison |
| Cumulative ACKs | ACK field acknowledges all bytes up to ack_num |
| Retransmission | Timeout-based (RTO from RTTEstimator) + fast retransmit on 3 dup-ACKs |
| Duplicate filtering | RecvBuffer discards segments whose end seq ≤ next_expected |
| Out-of-order delivery | Held in `_ooo` dict until gap is filled |
| Karn's algorithm | RTT samples only collected for non-retransmitted segments |

---

## File Map

```
ctp/
  packet.py       Packet dataclass, header struct, CRC checksum
  rtt.py          RTTEstimator — Jacobson SRTT/RTTVAR, exponential backoff
  congestion.py   BBR and CUBIC implementations
  buffer.py       SendWindow (send-side sliding window) and RecvBuffer
  socket.py       CTPSocket — public API, state machine, background threads

tools/
  send_file.py    CLI: send a file to a waiting receiver
  recv_file.py    CLI: receive a file and write to disk
  benchmark.py    Throughput and latency comparison: BBR vs CUBIC vs TCP

tests/
  test_packet.py      Round-trip, checksum, edge cases
  test_rtt.py         Convergence, backoff, bounds
  test_congestion.py  BBR state transitions, CUBIC growth and loss response
```
