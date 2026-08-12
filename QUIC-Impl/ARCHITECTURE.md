# Architecture

## Overview

```
Application
    │  open_stream() / recv_stream() / send() / read()
    ▼
QUICConnection                         quic/connection.py
    │
    ├── StreamManager                  quic/stream.py
    │     ├── SendStream[]             send buffer, flow-control, offset tracking
    │     └── RecvStream[]             reorder buffer, FIN detection
    │
    ├── RecoveryManager                quic/recovery.py
    │     ├── PacketNumberSpace × 3   Initial / Handshake / Application Data
    │     ├── RTT estimator           Jacobson EWMA (RFC 9002 §5)
    │     ├── Loss detection          reordering threshold + time threshold
    │     ├── PTO                     probe timeout
    │     └── Congestion control      simplified NewReno
    │
    ├── Frame codec                    quic/frames.py
    │     ├── encode_frame()
    │     └── decode_frames()
    │
    ├── Packet codec                   quic/packet.py
    │     ├── LongHeader  (Initial / Handshake)
    │     └── ShortHeader (1-RTT)
    │
    └── Varint codec                   quic/types.py
          encode_varint() / decode_varint()
```

---

## Packet Number Spaces

RFC 9000 defines three independent packet number spaces.  Each has its own
packet number counter, ACK state and loss timer.

| Space | Used for | Headers |
|-------|----------|---------|
| Initial | First flight: ClientHello | Long (type 0x00) |
| Handshake | Key confirmation | Long (type 0x02) |
| Application Data | All 1-RTT data | Short |

Keys used for each space are derived independently during TLS 1.3.  This
implementation uses a placeholder (XOR cipher) where the AEAD layer would sit.

---

## Packet Format

### Long header (Initial / Handshake)

```
  ┌─────────────────────────────────────────────────┐
  │ first_byte (8)   1|1|type(2)|rsv(2)|pn_len(2)  │
  ├─────────────────────────────────────────────────┤
  │ version (32)     0x00000001 = QUIC v1           │
  ├──────────────┬──────────────────────────────────┤
  │ dcid_len (8) │ dcid (dcid_len × 8)              │
  ├──────────────┴──────────────────────────────────┤
  │ scid_len (8) │ scid (scid_len × 8)              │
  ├─────────────────────────────────────────────────┤
  │ [token_len varint] [token]  (Initial only)      │
  ├─────────────────────────────────────────────────┤
  │ length (varint)   pn_len + payload bytes        │
  ├─────────────────────────────────────────────────┤
  │ packet_number (pn_len bytes)                    │
  ├─────────────────────────────────────────────────┤
  │ payload (frames)                                │
  └─────────────────────────────────────────────────┘
```

### Short header (1-RTT)

```
  ┌─────────────────────────────────────────────────┐
  │ first_byte (8)   0|1|spin|rsv(2)|kp|pn_len(2)  │
  ├─────────────────────────────────────────────────┤
  │ dcid (connection_id_len bytes)                  │
  ├─────────────────────────────────────────────────┤
  │ packet_number (pn_len bytes)                    │
  ├─────────────────────────────────────────────────┤
  │ payload (frames, AEAD-protected in real QUIC)   │
  └─────────────────────────────────────────────────┘
```

---

## Variable-Length Integer (Varint)

QUIC encodes integers 0–2^62−1 in 1, 2, 4 or 8 bytes.  The two MSBs of the
first byte encode the total byte count:

```
  00xxxxxx                          1 byte  (0–63)
  01xxxxxx xxxxxxxx                 2 bytes (0–16383)
  10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx  4 bytes (0–1073741823)
  11xxxxxx …                        8 bytes (0–4611686018427387903)
```

Varints appear in frame type codes, stream IDs, offsets, lengths, and all
ACK fields.

---

## Handshake State Machine

```
Client                                   Server
  IDLE ─connect()──────────────────────►  IDLE ─bind()/accept()──►
  INITIAL                                  INITIAL
   │  ──INITIAL(CRYPTO QUIC_HELLO)──►      │
   │                                       │ ──INITIAL(CRYPTO QUIC_HELLO)──►
   │  ◄──HANDSHAKE(CRYPTO QUIC_FINISHED)── │
   │                                       │ ──HANDSHAKE(CRYPTO QUIC_FINISHED)──►
   │  ──HANDSHAKE(CRYPTO QUIC_FINISHED)──► │
   HANDSHAKE                               │ ──1-RTT(HANDSHAKE_DONE)──►
   │  ◄──1-RTT(HANDSHAKE_DONE)──           │
   ESTABLISHED                             ESTABLISHED
```

In real QUIC this exchange carries TLS 1.3 ClientHello / ServerHello /
Certificate / Finished messages inside CRYPTO frames.  Here a plain-text
handshake token is used so the state machine and packet flow can be exercised
without a TLS library dependency.

---

## Stream Layer

### Send side

```
app.write(data)
    │
    ▼
SendStream._buf (bytearray)
    │
    │  pending_frames() — called by I/O loop
    ▼
StreamFrame(stream_id, offset, data, fin)
    │
    ▼  subject to:  stream.limit (MAX_STREAM_DATA)
                    connection._conn_send_limit (MAX_DATA)
    ▼
UDP datagram → peer
```

### Receive side

```
UDP datagram → QUICConnection._dispatch_packet()
    │
    ▼
decode_frames() → StreamFrame
    │
    ▼
StreamManager.on_stream_data_received()
    │
    ▼
RecvStream.receive(offset, data, fin)
    │  buffers out-of-order segments in _ooo dict
    │  delivers in-order bytes to _data when gap filled
    ▼
app.read(n)  ← blocks on threading.Event until data arrives
```

---

## Loss Recovery (RFC 9002 summary)

**RTT estimation** — Jacobson EWMA on `send_time → ACK_received` samples.
Ack delay (from the ACK frame) is subtracted before updating SRTT.

**Loss detection** — A packet is declared lost when:
- A packet with a higher PN is acknowledged, AND either
  - 3 or more packets with higher PNs have been ACKed (reordering threshold), OR
  - time since the packet was sent ≥ `1.125 × max(SRTT, latest_RTT)` (time threshold)

**PTO** — If no ACK is received within `SRTT + 4×RTTVAR + max_ack_delay`,
a probe packet (PING) is sent.  Each consecutive PTO doubles the timeout.

**Congestion control** — Simplified NewReno:
- Slow start: `cwnd += acked_bytes` per ACK
- Congestion avoidance: `cwnd += 1200 × acked/cwnd` per ACK
- On loss: `ssthresh = max(inflight × 0.5, 2400); cwnd = ssthresh`

---

## Flow Control

Two independent levels:

| Level | Frame that extends window | Applies to |
|-------|--------------------------|------------|
| Stream | `MAX_STREAM_DATA` | One stream's send offset |
| Connection | `MAX_DATA` | Sum of all streams' send offsets |

A sender blocks when `stream.offset >= stream.limit` or when
`connection.total_sent >= connection.limit`.  The receiver sends
`MAX_STREAM_DATA` / `MAX_DATA` frames when its buffers are drained past half.

---

## File Map

```
quic/
  types.py        Varint codec, frame/packet type constants, connection ID generator
  frames.py       All frame dataclasses, encode_frame(), decode_frames()
  packet.py       LongHeader, ShortHeader: to_bytes() and from_bytes()
  recovery.py     PacketNumberSpace, RecoveryManager (RTT, loss, PTO, congestion)
  stream.py       SendStream, RecvStream, StreamManager, flow control
  connection.py   QUICConnection: handshake state machine, I/O loop, public API

tools/
  transfer.py       CLI file send/receive over a single QUIC stream
  multiplex_demo.py Demo of N concurrent streams over one connection

tests/
  test_frames.py          Varint codec, all frame type round-trips, multi-frame payload
  test_packet_stream.py   Header serialization, stream send/recv, flow control
  test_recovery.py        RTT estimation, ACK processing, loss detection, PTO
```
