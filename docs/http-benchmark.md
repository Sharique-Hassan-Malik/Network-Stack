# HTTP Performance Analyzer — Architecture

## System Overview

Four layers: a shared ASGI test server, three protocol-specific benchmark clients, a statistical analysis layer and a FastAPI dashboard.

```
scripts/run_benchmark.py
        │
        ├─── Start hypercorn servers (HTTP/1.1 plain + HTTP/2+HTTP/3 over TLS)
        │
        ├─── BenchmarkRunner.run_all()
        │         │
        │         ├── HTTP1Benchmarker   (httpx, pool of 6 connections)
        │         ├── HTTP2Benchmarker   (httpx, 1 connection, multiplexed)
        │         └── HTTP3Benchmarker   (aioquic, QUIC streams)
        │
        ├─── analysis/stats.py  → print to terminal
        │
        └─── dashboard/app.py  → update in-memory state → browser poll
```

## Test Server — `server/app.py`

The ASGI application is protocol-agnostic — it handles `http` scope events identically regardless of whether the connection is HTTP/1.1, HTTP/2 or HTTP/3. Protocol differences are invisible to the application; the server (hypercorn) handles negotiation.

Endpoints are deliberately simple so measurement noise is minimised:

- Static byte-fill bodies of exactly 1 KB, 100 KB and 1 MB
- A `/resources` endpoint returning a JSON list of URLs so the benchmarker can discover and fetch assets in a second pass
- A `/simulate/hol` endpoint with a configurable `delay` query parameter, useful for programmatic HOL blocking tests
- `cache-control: no-store` on every response to prevent any caching

hypercorn is chosen as the server because it is one of the few Python ASGI servers that implements all three protocols natively in a single process:
- HTTP/1.1 via plain TCP or TLS
- HTTP/2 via TLS with ALPN `h2` negotiation
- HTTP/3 via QUIC (UDP port)

## HTTP/1.1 Client — `benchmark/http1.py`

`httpx.AsyncClient` with `http2=False` and a connection limit of 6 — matching the maximum number of parallel connections browsers use to a single origin. All requests are issued as concurrent `asyncio` tasks using `asyncio.gather`, so the 6-connection pool is exercised at capacity during concurrent scenarios.

Each request uses `client.stream()` to measure TTFB independently from the body transfer: TTFB is recorded when the first `await resp.aiter_bytes()` call returns, and the total time is recorded when the body is fully drained.

## HTTP/2 Client — `benchmark/http2.py`

`httpx.AsyncClient` with `http2=True` and `max_connections=1`. This forces all requests through a single TCP connection where they are multiplexed as HTTP/2 streams. The key measurement here is that even with dozens of concurrent `asyncio.gather` tasks, each stream begins transferring immediately rather than queuing for a free connection.

httpx relies on `httpcore`'s HTTP/2 implementation which handles stream lifecycle, flow control, HPACK header compression and the SETTINGS/WINDOW_UPDATE frame exchange transparently.

## HTTP/3 Client — `benchmark/http3.py`

HTTP/3 is built on QUIC — a UDP-based transport standardised in RFC 9000. Python has no built-in QUIC support; `aioquic` is the reference implementation.

The `_H3Client` class extends `QuicConnectionProtocol` and overrides `quic_event_received` to instantiate an `H3Connection` and forward incoming events to `http_event_received`. Stream state is tracked in three dicts keyed by stream ID: pending futures, accumulated headers and accumulated body bytes. When a stream's `data_received` event carries `stream_ended=True`, the future for that stream is resolved with `(headers, body)`.

`HTTP3Benchmarker.run()` uses `aioquic.asyncio.connect` as an async context manager to establish the QUIC connection, then issues all requests as concurrent tasks that each call `_H3Client.get()`. Because QUIC independently flow-controls every stream at the transport layer, this achieves true head-of-line-blocking elimination — a lost UDP packet on stream 3 does not block reading from stream 7.

If aioquic is not installed, the benchmarker returns placeholder error results rather than crashing, and the runner skips HTTP/3 columns.

## Benchmark Runner — `benchmark/runner.py`

`BenchmarkRunner.run_all()` executes scenarios in sequence. Within each scenario, all three protocol clients are invoked with `asyncio.gather` so they run concurrently and experience the same server load and network conditions.

The sequential scenario is handled separately: requests are issued one at a time in a loop so keep-alive connection reuse and per-request overhead are measured in isolation.

A warmup phase issues three throwaway requests on each protocol before timing begins to establish connections, negotiate TLS and trigger any JIT-related performance changes.

## Metrics — `benchmark/metrics.py`

`RequestResult` records all per-request timing. The `start_time` field stores an absolute epoch timestamp so waterfall diagrams can be rendered by subtracting the earliest `start_time` in the batch.

`ScenarioResult` aggregates a batch of `RequestResult` objects. Percentile computation (`p50`, `p95`, `p99`) sorts the values and returns the value at the corresponding index. Error results are excluded from statistical computation but counted separately in the `errors` field.

`to_dict()` serialises the full waterfall — every request's `start_ms`, `ttfb_ms` and `total_ms` relative to the first request in the batch — into a JSON-safe structure consumed by the dashboard.

## Dashboard — `dashboard/`

FastAPI holds results in a module-level `_state` dict. The benchmark runner calls `update_state()` after completion; the React frontend polls `GET /api/state` every 3 seconds.

The waterfall is rendered as a pure CSS layout: each request row contains two absolutely-positioned `<div>` elements (TTFB phase and transfer phase) whose `left` and `width` percentages are computed from the raw millisecond values scaled to the total window duration. All three protocol waterfalls share the same absolute time window (the maximum `end_ms` across all three) so the columns are directly comparable — a narrower bar means a faster request, not a different scale.

## Protocol Comparison — Key Differences Measured

| Dimension | HTTP/1.1 | HTTP/2 | HTTP/3 |
|-----------|----------|--------|--------|
| Connections | 6 parallel | 1 (multiplexed) | 1 QUIC (multiplexed) |
| HOL blocking | TCP + HTTP | TCP only | None |
| Handshake | TCP (1-2 RTT) + TLS (1-2 RTT) | Same | QUIC (1 RTT, 0-RTT resumption) |
| Header compression | None | HPACK | QPACK |
| Transport | TCP | TCP | UDP (QUIC) |

The `hol_blocking` scenario is designed to make the HTTP-layer HOL blocking in HTTP/1.1 visible: small requests block behind a large one within each connection. HTTP/2 eliminates this at the HTTP layer but remains subject to TCP-layer HOL blocking, which QUIC resolves completely.
