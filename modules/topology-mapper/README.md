# Network Topology Mapper

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; its RTT estimation and congestion control come from `netcore`.

Active network discovery tool that maps an entire subnet, infers its topology
through traceroute and renders an interactive force-directed graph in the browser.
Implements all probe logic from scratch — raw ICMP Echo, TCP SYN and UDP probes
are constructed manually without wrapping nmap or any other existing scanner.

---

## The Hard Part

**Raw packet construction** — ICMP, TCP SYN and UDP probes are assembled
byte-by-byte using `struct.pack`.  Each needs a correct Internet checksum
(RFC 1071 one's-complement sum), a pseudo-header for TCP and UDP checksums,
and accurate header lengths.  Getting any field wrong produces silently
dropped packets or incorrect responses.

**Concurrent probing with shared raw sockets** — Up to 64 hosts are probed
simultaneously.  A single pair of raw sockets (one ICMP, one TCP) receives all
replies across all hosts.  Two listener threads parse incoming packets and
update a shared result dict under a lock.  The probing threads wait on that
dict rather than opening per-host sockets, which keeps the file descriptor
count bounded.

**TTL-based traceroute in userspace** — Standard traceroute sends UDP probes
with incrementing TTL and waits for ICMP Time Exceeded replies.  The challenge
is matching each reply to the correct probe: the ICMP error payload includes
the original IP + UDP header, so the destination port (which we control) is
used as the per-hop identifier.

**OS fingerprinting without active probes** — Initial TTL is unobservable;
we see only the TTL as decremented by the routing path.  The trick is rounding
up to the nearest common initial value (64, 128 or 255).  Combined with TCP
window size and option fields this produces OS-family guesses with reasonable
confidence.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full four-phase pipeline, threading
model, packet layout and file map.

---

## Probe Types

| Probe | Socket type | Root? | Detects |
|-------|-------------|-------|---------|
| ICMP Echo | `SOCK_RAW IPPROTO_ICMP` | Yes | Any IP stack |
| TCP SYN | `SOCK_RAW IPPROTO_TCP` | Yes | Hosts with TCP services |
| UDP | `SOCK_RAW IPPROTO_UDP` | Yes | Hosts that return ICMP Port Unreachable |
| TCP connect | `SOCK_STREAM` | No | Open TCP ports only |

---

## Setup

```bash
python -m pip install -r requirements.txt
```

No third-party runtime dependencies.  Standard library only.  `pytest` is
required for tests.

---

## Usage

```bash
sudo python map.py --subnet 192.168.1.0/24
```

Full options:

```
--subnet        CIDR range to scan (required)
--ports         Comma or range list: 22,80,443-445 (default: top 100 ports)
--scan-method   connect | syn | udp  (default: connect)
--timeout       Per-host discovery timeout in seconds (default: 1.5)
--no-traceroute Skip traceroute (faster, less topology detail)
--no-rdns       Skip reverse DNS lookups
--output        HTML output file (default: topology.html)
--json          Also write a JSON results file
```

### Without root

Use `--scan-method connect` for TCP port scanning without raw socket access.
Host discovery falls back to TCP connect probes when ICMP raw sockets are
unavailable.

```bash
python map.py --subnet 192.168.1.0/24 --scan-method connect --no-traceroute
```

---

## Output

### Interactive HTML graph

The HTML file is self-contained.  Open it in any browser with no server needed.

- Nodes are colour-coded: purple = local machine, green = gateway, orange = router, blue = host
- Hover a node to see IP, hostname, OS guess and open ports
- Edge labels show measured RTT in milliseconds
- Drag to reposition; scroll to zoom; click to pin

### JSON report

```json
{
  "subnet": "192.168.1.0/24",
  "local_ip": "192.168.1.100",
  "gateway": "192.168.1.1",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "method": "icmp",
      "open_ports": [80, 443, 22],
      "hostname": "router.local",
      "os": { "family": "Linux", "version": "5.x / 6.x", "confidence": 72 }
    }
  ],
  "graph": { "nodes": [...], "edges": [...] }
}
```

---

## Running Tests

```bash
pytest tests/ -v
```

Tests cover packet construction, checksum correctness, header field values,
TCP option parsing, OS signature matching and HTML rendering.  No raw sockets
or network access are required.

---

## Relevant Coursework

- **Computer Communication and Networks** — IP, TCP and UDP header structure;
  ICMP message types; routing table format
- **Communication Systems** — TTL decay across hops; bandwidth-delay product
  in latency measurement
- **Signals and Systems** — analogies between hop-by-hop signal propagation
  and traceroute path reconstruction

---

## References

- RFC 792 — Internet Control Message Protocol
- RFC 793 — Transmission Control Protocol
- RFC 768 — User Datagram Protocol
- RFC 1071 — Computing the Internet Checksum
- Zalewski, M. — p0f v3 OS fingerprinting technical documentation
- Nmap — OS detection engine reference (nmap-os-db)
