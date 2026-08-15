# HTTP/1.1 vs HTTP/2 vs HTTP/3 Performance Analyzer

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; its RTT estimation and congestion control come from `netcore`.

Benchmarks the same ASGI application across all three HTTP protocol generations and visualises the differences in latency, throughput, multiplexing behaviour and head-of-line blocking in real time via a browser dashboard.

## The Hard Parts

**Multiplexing visualised as a waterfall.** HTTP/1.1 serialises requests within each TCP connection and browsers open at most 6 parallel connections. HTTP/2 multiplexes an unlimited number of streams over a single TCP connection. HTTP/3 does the same over QUIC, where each stream is independently flow-controlled at the transport layer — meaning packet loss on one stream does not stall others. The waterfall panel in the dashboard shows exactly when each request starts and finishes for each protocol, making the serialisation bottleneck in HTTP/1.1 immediately visible.

**Head-of-line blocking scenario.** The `hol_blocking` scenario issues one 1 MB resource and 19 small (1 KB) resources concurrently. In HTTP/1.1 the small requests queue behind the large one within each connection. In HTTP/2 they all run as independent streams and complete quickly even while the large transfer is in progress. The wall-time speedup between protocols on this scenario is typically the most dramatic of all benchmark cases.

**HTTP/3 via aioquic.** Python has no standard HTTP/3 client. `aioquic` is the reference implementation — it exposes raw QUIC stream management and a minimal HTTP/3 layer (`H3Connection`). The `HTTP3Benchmarker` builds a custom protocol handler directly on `QuicConnectionProtocol`, mapping stream IDs to `asyncio.Future` objects that resolve when the stream's data and end-of-stream flag arrive.

**Self-signed TLS for local H2 and H3.** HTTP/2 and HTTP/3 require TLS. The `server/certs.py` module uses the `cryptography` library to generate an RSA-2048 certificate with a SAN for `localhost` and `127.0.0.1`. The certificate is created once and reused across runs.

**All protocols benchmarked concurrently.** The runner issues all three protocol batches at the same time using `asyncio.gather` so wall-clock conditions are as similar as possible between protocols.

## Scenarios

| Scenario | Description | What it shows |
|----------|-------------|---------------|
| `single_small` | One 1 KB request | Baseline TTFB and connection overhead |
| `single_medium` | One 100 KB request | Transfer throughput |
| `single_large` | One 1 MB request | Transfer throughput at scale |
| `concurrent_small` | 20 concurrent 1 KB requests | Multiplexing vs connection-limit bottleneck |
| `hol_blocking` | 1 × 1 MB + 19 × 1 KB concurrent | Head-of-line blocking |
| `sequential` | 10 requests in series | Per-request overhead and keep-alive reuse |
| `mixed_sizes` | 8 small + 4 medium + 1 large | Real-world asset loading pattern |

## Tech Stack

- **Test server**: ASGI app served by hypercorn (supports HTTP/1.1, HTTP/2 and HTTP/3 in a single process)
- **HTTP/1.1 and HTTP/2 client**: httpx with HTTP/2 support via httpcore
- **HTTP/3 client**: aioquic — reference Python QUIC and HTTP/3 implementation
- **TLS**: cryptography library for self-signed certificate generation
- **Dashboard**: FastAPI serving a single-page React app with Recharts

## Setup

```bash
pip install -r requirements.txt
```

## Running the Benchmark

```bash
python scripts/run_benchmark.py
```

Open `http://localhost:9000` to view the live dashboard.

Options:

```bash
python scripts/run_benchmark.py --n-concurrent 30
python scripts/run_benchmark.py --no-dashboard          # terminal output only
python scripts/run_benchmark.py --output results.json   # save raw results
python scripts/run_benchmark.py --h1-port 8880 --h2-port 8443 --dashboard-port 9000
```

## Running Tests

```bash
pytest tests/ -v
```

## Dashboard Panels

**Latency** — grouped bar chart showing TTFB p50, p50, p95 and p99 in milliseconds for each protocol on the selected scenario.

**Throughput** — requests per second for each protocol.

**Waterfall** — per-request timeline showing time-to-first-byte (light) and transfer time (dark) for up to 30 requests. Horizontal scale is shared across all three protocol columns so the width difference is directly comparable.

**Table** — all raw metrics for every scenario and protocol in one scrollable table.

## File Map

| Path | Description |
|------|-------------|
| `server/app.py` | ASGI test application with small/medium/large/HOL endpoints |
| `server/certs.py` | Self-signed TLS certificate generator |
| `benchmark/metrics.py` | RequestResult and ScenarioResult data classes with percentile helpers |
| `benchmark/http1.py` | HTTP/1.1 async benchmarker (httpx, 6-connection pool) |
| `benchmark/http2.py` | HTTP/2 async benchmarker (httpx, single multiplexed connection) |
| `benchmark/http3.py` | HTTP/3 async benchmarker (aioquic, direct QUIC stream management) |
| `benchmark/runner.py` | Orchestrates all scenarios across all protocols |
| `analysis/stats.py` | Grouping, speedup table and console summary printer |
| `dashboard/app.py` | FastAPI dashboard API with in-memory state |
| `dashboard/static/index.html` | React dashboard with waterfall, latency and throughput panels |
| `scripts/run_benchmark.py` | Main entry point — starts servers, runs benchmark, updates dashboard |
| `tests/test_benchmark.py` | Unit tests for metrics, ASGI app and analysis |
