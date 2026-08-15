# Architecture

## Overview

Network Topology Mapper is a four-phase active reconnaissance tool:

```
CLI (map.py)
    │
    ├─ Phase 1: Discovery     DiscoveryScanner      ntm/discovery.py
    │     ICMP → TCP SYN → UDP
    │
    ├─ Phase 2: Port scan     scan_ports()          ntm/scanner.py
    │     connect / SYN / UDP
    │
    ├─ Phase 3: Topology      build_topology()      ntm/topology.py
    │     Gateway + traceroute → NetworkGraph
    │
    ├─ Phase 4: Fingerprint   fingerprint_os()      ntm/fingerprint.py
    │     TTL + window + TCP options → OS guess
    │
    └─ Render                 render_html()         ntm/renderer.py
          NetworkGraph → self-contained D3 HTML
```

---

## Probe Construction (ntm/probes.py)

All probe packets are built from scratch using `struct.pack` — no external
libraries.  The full IP + transport header is assembled, checksummed and
written into a raw socket.

```
IP header (20 bytes)
  ├── version + IHL
  ├── TTL (configurable per probe for traceroute)
  ├── protocol (ICMP=1, TCP=6, UDP=17)
  └── checksum (RFC 1071 Internet checksum)

ICMP Echo Request
  type=8 code=0 ident seq payload

TCP SYN
  sport dport seq ack dataoffset flags=0x002 window checksum urgent

UDP probe
  sport dport length checksum payload(4 bytes)
```

---

## Host Discovery (ntm/discovery.py)

Three probes are tried in sequence per host:

```
ICMP Echo Request  ──► ICMP Echo Reply (type 0)
TCP SYN to 80/443  ──► TCP SYN-ACK or RST
UDP to high port   ──► ICMP Port Unreachable (type 3 code 3)
```

A thread pool sends probes concurrently across all hosts (up to 64 workers).
Two dedicated listener threads read raw ICMP and TCP sockets, parse
arriving packets and update the result dict under a lock.

The per-host probe loop waits up to `timeout` seconds at each phase before
trying the next method.

---

## Port Scanning (ntm/scanner.py)

| Method  | How | Root needed |
|---------|-----|-------------|
| connect | Full TCP 3-way handshake | No |
| syn | Raw TCP SYN; parse SYN-ACK or RST | Yes |
| udp | Raw UDP; wait for ICMP Port Unreachable | Yes |

Port states:

| State | Meaning |
|-------|---------|
| OPEN | SYN-ACK received or connect() succeeded |
| CLOSED | RST received or ConnectionRefused |
| FILTERED | No response within timeout |
| OPEN_FILTERED | UDP: no response (open or firewall) |

---

## Topology Inference (ntm/topology.py)

1. **Default gateway** is read from `/proc/net/route` (Linux) or parsed from
   `ip route show default` output.

2. **Traceroute** sends UDP probes with TTL starting at 1.  Each ICMP
   Time Exceeded reply reveals an intermediate router.  Up to 20 hops
   are probed with 2 retries per hop.

3. **NetworkGraph** stores nodes (hosts and routers) and directed edges
   (observed hop pairs).  Edges carry RTT measurements from the traceroute.

4. Reverse DNS lookups (optional) are attempted for all graph nodes.

---

## OS Fingerprinting (ntm/fingerprint.py)

Fingerprinting is passive — fields observed in packets already received:

| Field | Where it comes from |
|-------|---------------------|
| TTL | IP header of any arriving packet |
| DF bit | IP flags field |
| Window | TCP window field in SYN or SYN-ACK |
| MSS | TCP option kind 2 |
| Window scale | TCP option kind 3 |
| SACK permitted | TCP option kind 4 |

A signature database maps TTL range × window range (± TCP options) to
OS families.  Each signature is scored; the highest-scoring match wins.
Initial TTL is inferred by rounding up to the nearest common value (64,
128 or 255) since each router decrements by 1.

---

## Renderer (ntm/renderer.py)

Outputs a single self-contained HTML file with:

- D3 v7 force-directed graph (loaded from CDN)
- Graph data embedded as JSON in the `<script>` block
- Dark-themed CSS; nodes colour-coded by role
- Hover tooltip showing IP, hostname, OS guess and open ports
- Drag to reposition; scroll to zoom; click to pin/unpin a node
- Edge labels show RTT in milliseconds

---

## File Map

```
ntm/
  probes.py       IP, ICMP, TCP and UDP packet construction; checksum
  discovery.py    Host discovery: ICMP + TCP SYN + UDP, parallel with raw sockets
  scanner.py      Port scanner: connect, SYN and UDP methods; PortState enum
  fingerprint.py  OS fingerprinting from TTL, window, TCP options
  topology.py     Traceroute, gateway detection, NetworkGraph
  renderer.py     D3 force-graph HTML renderer

map.py            CLI entry point: orchestrates all four phases
tests/
  test_probes.py              Packet construction, checksum, header fields
  test_fingerprint_topology.py  OS signatures, TCP option parsing, NetworkGraph
  test_renderer.py            HTML output, JSON embedding, edge cases
```
