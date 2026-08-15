# Architecture

## Overview

```
  OpenFlow switches (OVS / physical)
          │  TCP port 6653
          ▼
  OpenFlowServer              sdn/channel.py
    SwitchConnection[]
          │  callbacks on message type
          ▼
  SDNController               sdn/controller.py
    │
    ├── MACTable               sdn/mac_table.py
    │     dpid → {mac → (port, timestamp)}
    │
    ├── TopologyGraph          sdn/topology.py
    │     switches, links, hosts
    │     Dijkstra shortest-path
    │     Prim spanning tree
    │
    ├── LoadBalancer           sdn/load_balancer.py
    │     VIP → backend pool
    │     round-robin / least-conn
    │     per-flow affinity table
    │
    ├── TrafficShaper          sdn/traffic_shaper.py
    │     OF 1.3 Meter tables (DROP / DSCP_REMARK)
    │     SET_QUEUE actions
    │
    ├── FailoverManager        sdn/failover.py
    │     PORT_STATUS handler
    │     heartbeat timeout monitor
    │     path recomputation + rule reinstall
    │
    └── REST API (HTTP :8080)  sdn/controller.py
          GET  /topology
          GET  /switches
          GET  /lb
          GET  /macs
          GET  /failover
          POST /lb/backend
          POST /shaper/meter
```

---

## OpenFlow 1.3 Message Subset

```
Handshake:
  Controller → Switch   HELLO, FEATURES_REQUEST
  Switch → Controller   HELLO, FEATURES_REPLY

Keep-alive:
  Switch → Controller   ECHO_REQUEST
  Controller → Switch   ECHO_REPLY

Forwarding:
  Switch → Controller   PACKET_IN
  Controller → Switch   PACKET_OUT
  Controller → Switch   FLOW_MOD (ADD / DELETE)

Topology:
  Switch → Controller   PORT_STATUS

Stats:
  Controller → Switch   MULTIPART_REQUEST (PORT_STATS)
  Switch → Controller   MULTIPART_REPLY
  Controller → Switch   BARRIER_REQUEST
```

---

## Packet Format — Flow-Mod Body

```
  ┌──────────────────────────────────────────────────┐
  │ cookie        (64-bit)                           │
  │ cookie_mask   (64-bit)                           │
  │ table_id      (8-bit)                            │
  │ command       (8-bit)  ADD=0 MODIFY=1 DELETE=3   │
  │ idle_timeout  (16-bit)                           │
  │ hard_timeout  (16-bit)                           │
  │ priority      (16-bit)                           │
  │ buffer_id     (32-bit)                           │
  │ out_port      (32-bit)                           │
  │ out_group     (32-bit)                           │
  │ flags         (16-bit) + 2-byte pad              │
  ├──────────────────────────────────────────────────┤
  │ OXM match structure                              │
  ├──────────────────────────────────────────────────┤
  │ Instructions (OFPIT_APPLY_ACTIONS wrapping        │
  │  OFPAT_OUTPUT or other actions)                  │
  └──────────────────────────────────────────────────┘
```

OXM (OpenFlow Extensible Match) fields encode match criteria as TLVs:

```
  ┌──────────────┬──────────────┬──────────────────┐
  │ oxm_class(16)│field(7)+hm(1)│ length(8) │ value │
  └──────────────┴──────────────┴──────────────────┘
```

Supported match fields: `in_port`, `eth_dst`, `eth_src`, `eth_type`,
`ipv4_src`, `ipv4_dst`, `ip_proto`, `tcp_dst`, `udp_dst`.

---

## Control Plane Logic

### Packet-In handler

```
Receive PACKET_IN
    │
    ├── eth_type == LLDP?  ──► record inter-switch link → topology
    │
    ├── Learn eth_src → in_port in MACTable
    ├── Update host location in TopologyGraph
    ├── record_heartbeat(dpid, in_port) → FailoverManager
    │
    ├── TCP SYN to VIP?  ──► LoadBalancer.get_backend()
    │                         install rewrite flow rule
    │                         forward to backend port
    │
    ├── eth_dst known?  ──► install L2 flow rule (priority 10, idle_timeout 30s)
    │                       send buffered packet to out_port
    │
    └── eth_dst unknown?  ──► flood on spanning-tree ports
                               (prevents broadcast loops in ring topologies)
```

### Flow priorities

| Priority | Rule | Description |
|----------|------|-------------|
| 0        | Table-miss | Send all unmatched packets to controller |
| 10       | L2 forward | Match in_port + eth_dst → output port |
| 20       | LB redirect | Match ip_dst=VIP + tcp_dst=vport → backend port |

---

## Topology and Path Computation

### Link discovery (LLDP)

The controller periodically (every 5 s) injects LLDP frames via `PACKET_OUT`
on every switch port.  Each LLDP frame encodes the originating (dpid, port)
in the Chassis ID and Port ID TLVs.  When a switch receives an LLDP and sends
it as a `PACKET_IN`, the controller reads out the source dpid/port and records
the link: `(src_dpid, src_port) → (dst_dpid=conn.dpid, dst_port=in_port)`.

### Dijkstra shortest-path

The topology graph stores adjacency as a dict `dpid → [dpid, ...]` built from
the link set.  Dijkstra runs with a binary heap (Python `heapq`), hop count
as edge weight.  Used by FailoverManager to compute new paths after a failure.

### Spanning tree (Prim's algorithm)

Used for broadcast/flood traffic to prevent loops in ring or meshed topologies.
Prim starts from any switch and greedily adds the cheapest edge to an unvisited
node.  The result is a dict `dpid → set[port]` — only ports in the tree are
used for flooding; all other ports suppress broadcast.

---

## Load Balancer

The load balancer maps a virtual IP:port to a pool of real backends.

```
Client  ──TCP SYN──►  VIP:80
                          │
                    SDN controller intercepts via Packet-In
                    selects backend (round-robin or least-conn)
                    installs flow rule: dst=VIP:80 → output(backend_port)
                    sends buffered packet to backend port
                          │
                     Backend server
```

Flow affinity is maintained by keying on `(client_ip, client_port)`.  The
same flow key always returns the same backend until the entry expires
(`flow_timeout`, default 300 s) or the backend goes down.  On backend removal
all flows mapped to it are evicted so they are re-mapped on the next packet.

---

## Failover

```
PORT_STATUS (DELETE or state=LINK_DOWN)
    │
    ▼
FailoverManager._handle_failure(dpid, port)
    │
    ├── topology.remove_link(dpid, port)     ← both directions removed
    │
    ├── _recompute_paths(dpid)
    │     for each host pair:
    │       shortest_path(src_dpid, dst_dpid)
    │       _install_path() → install_fn(dpid, rules)
    │
    └── notify callbacks

PORT_STATUS (ADD / MODIFY, state=0)
    │
    ▼
FailoverManager._handle_recovery(dpid, port)
    │
    └── _recompute_paths(dpid)
```

The heartbeat monitor fires `_handle_failure` for any `(dpid, port)` that
has not received a packet for `hb_timeout` (15 s default).

---

## Traffic Shaping

OF 1.3 Meter tables allow rate limiting at the switch:

```
METER_MOD (ADD)
  meter_id = N
  flags    = KBPS | STATS
  band:
    type       = DROP (or DSCP_REMARK)
    rate       = 1000  (kbps)
    burst_size = 200   (kbps)

FLOW_MOD with METER instruction prepended:
  OFPIT_METER  meter_id=N
  OFPIT_APPLY_ACTIONS  output(port)
```

The `TrafficShaper` generates both the `METER_MOD` message and the
`OFPIT_METER` instruction bytes that are prepended to a flow's instruction
list.

---

## File Map

```
sdn/
  openflow.py       OF 1.3 message structs, OXM match builder, action helpers
  channel.py        TCP server, per-switch message loop, SwitchConnection
  mac_table.py      Per-datapath MAC→port table with idle-timeout aging
  topology.py       TopologyGraph: switches, links, hosts, Dijkstra, Prim
  load_balancer.py  LoadBalancer: VIP→backend pool, round-robin, least-conn
  traffic_shaper.py TrafficShaper: OF Meter tables, SET_QUEUE actions
  failover.py       FailoverManager: port-status handling, path recomputation
  controller.py     SDNController: wires all modules, Packet-In handler, REST API

tools/
  run_controller.py   Start the controller (OF :6653, REST :8080)
  mininet_topo.py     Three-switch ring topology for Mininet testing

tests/
  test_openflow.py       OF header, actions, OXM match, Flow-Mod, Packet-Out
  test_mac_topology.py   MACTable aging, TopologyGraph path/spanning-tree
  test_lb_shaper.py      LoadBalancer affinity/eviction, TrafficShaper meters
  test_failover.py       Port-status handling, recovery, heartbeat, callbacks
```
