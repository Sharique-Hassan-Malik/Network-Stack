# QUIC Protocol Implementation

A subset of the QUIC transport protocol (RFC 9000) implemented from scratch in
Python over UDP.  Covers connection establishment, stream multiplexing, two-level
flow control and loss recovery including PTO and congestion control.

---

## The Hard Part

**Variable-length integers everywhere** — QUIC uses varints (1, 2, 4 or 8 bytes
determined by the two MSBs of the first byte) for frame types, stream IDs,
offsets, lengths and sequence numbers.  Every frame field is a varint, so the
codec must be correct at every boundary, including when a 2-byte varint follows
a 4-byte one mid-packet.

**Three independent packet number spaces** — Initial, Handshake and Application
Data each maintain their own packet number counter, ACK state and loss timer.
An ACK in the Handshake space says nothing about Application Data packets, so
loss detection must track which space each packet belongs to and only process
ACKs within their respective space.

**Stream flow control at two levels** — Every STREAM frame is gated by both the
per-stream send window (`MAX_STREAM_DATA`) and the connection-wide window
(`MAX_DATA`).  A sender that is allowed by the stream but blocked at the connection
level must buffer the data rather than drop it, and emit a `DATA_BLOCKED` frame
instead of a `STREAM_DATA_BLOCKED` frame.

**Out-of-order delivery with FIN** — QUIC streams can receive the FIN offset
before all data arrives (FIN only marks the final offset, not that all preceding
bytes have been received).  The receive buffer must hold out-of-order segments,
detect when the gap is filled and only deliver bytes in-order, while correctly
setting `is_fin_read()` only after the last byte has been consumed by the
application.

**Loss detection without sequence numbers** — Unlike TCP, QUIC packet numbers
are never retransmitted; a retransmission of the same data uses a new packet
number.  Loss detection therefore compares the packet number of the lost packet
against the largest ACKed number, not the data sequence number.  This also means
retransmission ambiguity (Karn's algorithm) does not apply to QUIC.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full diagram, packet layout, handshake
state machine, stream send/receive data flow and loss recovery summary.

---

## Implemented Subset

| Feature | RFC reference | Status |
|---------|---------------|--------|
| Variable-length integers | RFC 9000 §16 | ✓ |
| Long header (Initial, Handshake) | RFC 9000 §17.2 | ✓ |
| Short header (1-RTT) | RFC 9000 §17.3 | ✓ |
| PADDING, PING, ACK frames | RFC 9000 §19.1–19.3 | ✓ |
| CRYPTO frames | RFC 9000 §19.6 | ✓ |
| STREAM frames (OFF, LEN, FIN) | RFC 9000 §19.8 | ✓ |
| MAX_DATA, MAX_STREAM_DATA | RFC 9000 §19.9–19.10 | ✓ |
| MAX_STREAMS | RFC 9000 §19.11 | ✓ |
| DATA_BLOCKED, STREAM_DATA_BLOCKED | RFC 9000 §19.12–19.13 | ✓ |
| CONNECTION_CLOSE | RFC 9000 §19.19 | ✓ |
| HANDSHAKE_DONE | RFC 9000 §19.20 | ✓ |
| Stream multiplexing | RFC 9000 §2 | ✓ |
| Two-level flow control | RFC 9000 §4 | ✓ |
| RTT estimation | RFC 9002 §5 | ✓ |
| Loss detection (reordering + time threshold) | RFC 9002 §6 | ✓ |
| PTO probe timeout | RFC 9002 §6.2 | ✓ |
| NewReno congestion control | RFC 9002 §7 | ✓ (simplified) |
| TLS 1.3 AEAD encryption | RFC 9001 | placeholder XOR |
| Connection migration | RFC 9000 §9 | not implemented |
| Version negotiation | RFC 9000 §6 | not implemented |
| 0-RTT data | RFC 9000 §5.6 | not implemented |

---

## Setup

```bash
python -m pip install -r requirements.txt
```

Standard library only.  `pytest` is required for tests.

---

## Running Tests

```bash
pytest tests/ -v
```

77 tests covering varint encoding at every boundary, all frame type round-trips,
packet header parsing, stream send/receive ordering, flow control and loss recovery.

---

## File Transfer

```bash
# Terminal 1 — receiver
python tools/transfer.py recv --port 4433 --output received.bin

# Terminal 2 — sender
python tools/transfer.py send --host 127.0.0.1 --port 4433 --file myfile.bin
```

---

## Stream Multiplexing Demo

```bash
python tools/multiplex_demo.py
# or
python tools/multiplex_demo.py --streams 8 --payload 32768
```

Opens N bidirectional streams concurrently over a single UDP flow and verifies
that each stream delivers its data independently.  This demonstrates QUIC's
key transport advantage: no head-of-line blocking between streams even if one
stream's packets are delayed.

---

## Relevant Coursework

- **Computer Communication and Networks** — transport layer design, reliability
  mechanisms, flow and congestion control, connection state machines
- **Communication Systems** — RTT estimation as a discrete-time filter (EWMA is
  a first-order IIR filter); bandwidth-delay product
- **Probability Methods in Engineering** — Jacobson's EWMA estimator; the
  RTTVAR term is an estimate of the mean absolute deviation of RTT samples

---

## References

- RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001 — Using TLS to Secure QUIC
- RFC 9002 — QUIC Loss Detection and Congestion Control
- Cardwell et al. (2017). QUIC Loss Recovery and Congestion Control. IETF Draft.
- Iyengar, J. & Thomson, M. (eds.) — QUIC Working Group (quicwg.org)
