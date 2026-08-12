# Networking & Distributed Systems

Protocols and distributed systems built from the wire up: a QUIC implementation, a custom reliable transport, an SDN controller, Raft consensus, a distributed task queue, and a vector database — each from scratch.

A collection of 8 self-contained projects. Each lives in its own subdirectory with its own `README.md` and `LICENSE` (most also include an `ARCHITECTURE.md` and a test suite), and can be built and run independently.

## Projects

| project | what it is |
|---|---|
| [`Custom-Transport-Protocol`](./Custom-Transport-Protocol) | A reliable transport protocol implemented over UDP in Python, featuring BBR and CUBIC congestion control. |
| [`HTTP-Performance-Analyzer`](./HTTP-Performance-Analyzer) | Benchmarks the same ASGI application across all three HTTP protocol generations and visualises the differences in latency, throughput, multiplexing… |
| [`Network-Topology-Mapper`](./Network-Topology-Mapper) | Active network discovery tool that maps an entire subnet, infers its topology through traceroute and renders an interactive force-directed graph in… |
| [`QUIC-Impl`](./QUIC-Impl) | A subset of the QUIC transport protocol (RFC 9000) implemented from scratch in Python over UDP. |
| [`Raft-KV`](./Raft-KV) | A Raft consensus implementation paired with a linearisable key-value store. |
| [`SDN-Controller`](./SDN-Controller) | An OpenFlow 1.3 SDN controller managing a virtual network — implementing load balancing, traffic shaping and automatic failover with all control-pl… |
| [`Taskqueue`](./Taskqueue) | A Celery-like distributed task queue built entirely from scratch — custom TCP broker protocol, worker process pool, SQLite result backend and a web… |
| [`VecDB`](./VecDB) | A vector similarity search engine built entirely from first principles. |

## Repository layout

Each subdirectory is a standalone project; there is no shared build. Enter one and follow its README:

```bash
cd Custom-Transport-Protocol
cat README.md
```

## License

MIT — see the `LICENSE` file in each project.
