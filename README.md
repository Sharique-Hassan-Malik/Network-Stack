# Network Stack

Two transports built from the packet up, a protocol benchmark, a topology
mapper, an SDN controller and a BGP hijack analyser — sharing one RTT
estimator, one set of congestion controllers, and one way of reporting a
measurement.

```
net modules                       # what is here, and how to run each alone
net congestion --loss 0.01        # Reno vs CUBIC vs BBR on one bottleneck
net bench https://example.com     # HTTP/1.1 vs /2 vs /3
net map 192.0.2.0/24              # traceroute, scan, fingerprint, graph
net bgp updates.mrt               # origin hijacks, sub-prefix hijacks, bogons
```

```
$ net congestion --loss 0.01 --rounds 200

  10 Mbit/s, 50 ms RTT, queue 64 kB, loss 1.00%, 200 round trips

  algorithm    throughput   mean RTT  utilisation   final cwnd
  ------------------------------------------------------------
  reno           6.26 Mb/s     77.7 ms         63%       46,719
  cubic          7.81 Mb/s     63.2 ms         78%       55,908
  bbr            6.96 Mb/s     71.0 ms         70%       89,598
```

## The six modules

| Module | What it is |
|---|---|
| [`quic`](modules/quic) | QUIC: packet and frame encoding, streams with flow control, and loss detection and recovery per RFC 9002. |
| [`transport`](modules/transport) | A reliable protocol over UDP from scratch — handshake, sequencing, selective acknowledgement, pluggable congestion control. |
| [`http-benchmark`](modules/http-benchmark) | HTTP/1.1, /2 and /3 measured against the same server under concurrency, with a dashboard. |
| [`topology-mapper`](modules/topology-mapper) | Traceroute, port scanning and OS fingerprinting assembled into a graph. |
| [`sdn-controller`](modules/sdn-controller) | An OpenFlow controller: MAC learning, shortest-path forwarding, load balancing, failover. |
| [`bgp-analyzer`](modules/bgp-analyzer) | Routing-update analysis: origin hijacks, sub-prefix hijacks, bogons, AS-path anomalies. |

## What they share, and why

`netcore/` is the part that was written more than once.

**One RTT estimator** ([`netcore/rtt.py`](netcore/rtt.py)). Both transports
implemented RFC 6298 and arrived at the same constants with different framing.
QUIC's handled the peer's reported ack delay and a clock-granularity floor; the
other had explicit Karn backoff. Neither was wrong — keeping two of them was.
The shared one is the union, with the extras defaulting off so a plain RFC 6298
stack behaves exactly as before.

**One set of congestion controllers** ([`netcore/congestion.py`](netcore/congestion.py)).
The reliable transport had CUBIC and BBR. QUIC had a Reno welded into its
recovery manager with no way to swap it. All three now sit behind one
interface, so **QUIC gained CUBIC and BBR**, which it never had:

```python
RecoveryManager(congestion="bbr")     # or "cubic", or an instance you built
```

**One measurement type** ([`netcore/measure.py`](netcore/measure.py)). Six tools
measuring latency six ways, so their numbers could not go in one table. Folding
them onto one definition settles what a percentile means: index arithmetic
over ten samples returns the *ninth* value as the p99 and the fifth as the p50,
under-reporting exactly the tail a benchmark exists to report. The shared
function interpolates instead.

**What is deliberately not shared.** The topology mapper's graph is IP-level,
discovered by traceroute, with RTT-weighted edges. The SDN controller's is
switch-and-port level, keyed by datapath ID, and drives flow-rule installation.
They look similar and are not: merging them would either lose the port detail
the controller needs or bolt datapath IDs onto a traceroute. Only one of them
had a shortest-path implementation, so there was no duplicate to remove. They
stay separate.

## Using one module on its own

Each module folder is a self-contained source root with its own CLI and tests:

```bash
cd modules/quic            && python tools/transfer.py
cd modules/transport       && python tools/send_file.py
cd modules/http-benchmark  && python scripts/run_benchmark.py
cd modules/topology-mapper && python map.py 192.0.2.0/24
cd modules/sdn-controller  && python tools/run_controller.py
cd modules/bgp-analyzer    && python -m bgp_analyzer.cli
```

`netcore` is stdlib-only, so importing the shared estimator or controllers
costs a standalone module no dependencies.

## Install

```bash
pip install -e .              # the core and both transports
pip install -e ".[bench]"     # adds httpx and aioquic for the HTTP benchmark
```

## Tests

```bash
pytest                        # everything
pytest modules/quic           # one module
```

## Licence

MIT — see [LICENSE](LICENSE).
