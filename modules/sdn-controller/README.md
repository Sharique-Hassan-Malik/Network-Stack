# SDN Controller

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; its RTT estimation and congestion control come from `netcore`.

An OpenFlow 1.3 SDN controller managing a virtual network — implementing load
balancing, traffic shaping and automatic failover with all control-plane logic
written from scratch.  Designed to connect to Open vSwitch via a standard
Mininet topology.

---

## The Hard Part

**OpenFlow message framing** — Every OpenFlow message begins with an 8-byte
header containing the total wire length.  The TCP receiver must buffer bytes
until a complete message is available, then dispatch exactly that many bytes
to the handler, leaving any remainder in the buffer for the next message.
Framing errors cause every subsequent message to be misaligned and silently
corrupt.

**OXM match encoding** — OpenFlow 1.3 uses Extensible Match (OXM) TLVs for
flow match fields.  Each TLV carries a class (16-bit), field+hasmask (8-bit)
and length (8-bit), followed by the value.  The match structure must be
8-byte aligned and the `length` field in the enclosing match header counts
only the OXM bytes, not the padding.  A match with no fields is still 4 bytes
(type + length fields), and the alignment padding is computed separately.

**Broadcast loop prevention** — A ring or mesh of switches will loop broadcast
frames indefinitely without loop prevention.  The controller computes a
spanning tree (Prim's algorithm) over the topology graph and restricts flood
traffic to spanning-tree ports only.  When a link fails, the spanning tree is
recomputed and new flood rules are pushed within one RTT of the failure
detection.

**Flow affinity under failure** — The load balancer maintains per-flow backend
assignments keyed on `(client_ip, client_port)`.  When a backend is removed
or deactivated, those flow entries must be evicted immediately so that the
next packet re-triggers the selection algorithm.  Entries that are not
explicitly released must age out via `flow_timeout` to avoid unbounded memory
growth.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full pipeline: message framing,
OXM encoding, control-plane decision tree, topology discovery, load-balancer
flow affinity and failover path recomputation.

---

## Setup

```bash
python -m pip install -r requirements.txt
```

No third-party runtime dependencies.  `pytest` is required for tests.

For the Mininet topology script, Open vSwitch and Mininet must be installed:

```bash
sudo apt install mininet openvswitch-switch
```

---

## Running Tests

```bash
pytest tests/ -v
```

80 tests covering OF message serialization, OXM match construction, MAC table
aging, Dijkstra shortest-path, spanning tree, load-balancer affinity and
eviction, meter configuration and failover event handling.

---

## Starting the Controller

```bash
python tools/run_controller.py
# or with options:
python tools/run_controller.py --of-port 6653 --rest-port 8080 \
    --vip 10.0.0.100 --vport 80 --lb-policy least_conn
```

---

## Connecting a Virtual Network (Mininet)

In a separate terminal:

```bash
sudo python tools/mininet_topo.py --controller 127.0.0.1 --port 6653
```

This creates a three-switch ring (s1–s2–s3) with two hosts per switch and
connects all switches to the running controller via OpenFlow 1.3.

Inside Mininet:

```
mininet> h1 ping h4
mininet> h2 iperf -s &
mininet> h5 iperf -c 10.0.0.2
```

---

## REST API

Once running, the controller exposes a JSON REST API:

```bash
# Network topology
curl http://localhost:8080/topology

# Connected switches
curl http://localhost:8080/switches

# MAC learning table
curl http://localhost:8080/macs

# Load balancer stats
curl http://localhost:8080/lb

# Active link failures
curl http://localhost:8080/failover

# Add a backend to the load balancer
curl -X POST http://localhost:8080/lb/backend \
     -H "Content-Type: application/json" \
     -d '{"ip":"10.0.0.5","port":80,"mac":"00:00:00:00:00:05","weight":2}'

# Add a rate-limiting meter (1 Mbps)
curl -X POST http://localhost:8080/shaper/meter \
     -H "Content-Type: application/json" \
     -d '{"rate_kbps":1000,"burst_kbps":200}'
```

---

## Load Balancing

The controller intercepts TCP SYN packets destined for the virtual IP and
rewrites the forwarding decision in hardware via a flow rule.

```
                    ┌──── Backend 10.0.0.1:80  (weight 1)
Client ──► VIP:80 ──┼──── Backend 10.0.0.2:80  (weight 2)
                    └──── Backend 10.0.0.3:80  (weight 1)
```

Policies:
- `round_robin` — rotates through backends weighted by their `weight` field
- `least_conn`  — always picks the backend with the lowest `connections/weight` ratio

Flow affinity is maintained per `(client_ip, client_port)` for 300 s.

---

## Traffic Shaping

Meters are installed on the switch using `OFPT_METER_MOD`.  Two band types:
- `DROP` — packets exceeding the rate are dropped at the switch
- `DSCP_REMARK` — packets exceeding the rate have their DSCP bits reduced

Meters are associated with flows via the `OFPIT_METER` instruction prepended
to the flow's instruction list.

---

## Automatic Failover

When a link fails (detected via `PORT_STATUS` or heartbeat timeout):

1. The failed link is removed from the topology graph (both directions).
2. Dijkstra recomputes paths for all affected host pairs.
3. New `FLOW_MOD` rules are pushed to affected switches.
4. Registered callbacks are notified.

Recovery is detected the same way and triggers another recompute.

---

## Relevant Coursework

- **Computer Communication and Networks** — OpenFlow protocol, SDN architecture,
  flow table design, spanning tree to prevent loops
- **Communication Systems** — bandwidth-delay product in traffic shaping;
  token-bucket meter model
- **Probability Methods in Engineering** — least-connections load balancing as
  a min-cost assignment; weighted round-robin as a discrete uniform distribution

---

## References

- OpenFlow Switch Specification v1.3.5 — ONF-TS-011
- McKeown, N. et al. (2008). OpenFlow: Enabling Innovation in Campus Networks. *ACM SIGCOMM*.
- Ryu SDN Framework documentation — ryu.readthedocs.io (reference for OF 1.3 message structure)
- Mininet documentation — mininet.org
