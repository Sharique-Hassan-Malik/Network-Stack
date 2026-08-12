"""
Network topology inference.

Steps
-----
1. Identify the default gateway (read from the routing table).
2. Run a TTL-limited traceroute to each discovered host to enumerate
   intermediate routers.
3. Build a NetworkGraph: nodes are hosts and routers; edges are
   directly-observed hop relationships.

Traceroute sends UDP probes with incrementing TTL (like Unix traceroute)
and listens for ICMP Time Exceeded replies.  Up to 30 hops are tried.
"""

import ipaddress
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from .probes import udp_probe

_MAX_HOPS    = 20
_PROBE_PORT  = 33434    # UDP base port (incremented per hop)
_TIMEOUT     = 1.0      # seconds per hop
_RETRIES     = 2        # probes per TTL level


@dataclass
class Hop:
    ttl:     int
    ip:      str
    rtt_ms:  float


@dataclass
class TracerouteResult:
    destination: str
    hops:        list[Hop] = field(default_factory=list)
    reached:     bool      = False


@dataclass
class NetworkNode:
    ip:           str
    is_gateway:   bool = False
    is_router:    bool = False
    hostname:     Optional[str] = None


@dataclass
class NetworkEdge:
    src: str
    dst: str
    rtt_ms: float = 0.0


@dataclass
class NetworkGraph:
    nodes: dict[str, NetworkNode] = field(default_factory=dict)
    edges: list[NetworkEdge]      = field(default_factory=list)

    def add_node(self, ip: str, **kwargs) -> None:
        if ip not in self.nodes:
            self.nodes[ip] = NetworkNode(ip=ip, **kwargs)
        else:
            for k, v in kwargs.items():
                setattr(self.nodes[ip], k, v)

    def add_edge(self, src: str, dst: str, rtt_ms: float = 0.0) -> None:
        for e in self.edges:
            if e.src == src and e.dst == dst:
                return
        self.edges.append(NetworkEdge(src=src, dst=dst, rtt_ms=rtt_ms))

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "ip":          n.ip,
                    "is_gateway":  n.is_gateway,
                    "is_router":   n.is_router,
                    "hostname":    n.hostname,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "rtt_ms": round(e.rtt_ms, 3)}
                for e in self.edges
            ],
        }


# ── gateway detection ─────────────────────────────────────────────────────────

def default_gateway() -> Optional[str]:
    """
    Parse the kernel routing table to find the default gateway.

    On Linux reads /proc/net/route.  On other platforms falls back to
    parsing `ip route` or `route -n` output.
    """
    if sys.platform == "linux":
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 8:
                        continue
                    # Destination = 00000000 means default route
                    if parts[1] == "00000000":
                        raw = bytes.fromhex(parts[2])
                        gw  = socket.inet_ntoa(raw[::-1])
                        if gw != "0.0.0.0":
                            return gw
        except OSError:
            pass

    # Fallback: parse `ip route` output
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, timeout=3,
            stderr=subprocess.DEVNULL,
        )
        for token in out.split():
            try:
                addr = ipaddress.ip_address(token)
                return str(addr)
            except ValueError:
                continue
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return None


# ── traceroute ────────────────────────────────────────────────────────────────

def traceroute(destination: str, max_hops: int = _MAX_HOPS) -> TracerouteResult:
    """
    UDP/ICMP traceroute to destination.
    Requires root (raw socket) or CAP_NET_RAW.
    """
    result = TracerouteResult(destination=destination)

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(_TIMEOUT)
    except PermissionError:
        return result   # silently skip — caller checks reached flag

    src = _local_src(destination)

    try:
        for ttl in range(1, max_hops + 1):
            hop_ip: Optional[str] = None
            rtt_ms = 0.0

            for _ in range(_RETRIES):
                sport = 49152 + ttl
                dport = _PROBE_PORT + ttl
                pkt   = udp_probe(src, destination, sport, dport, ttl=ttl)

                send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                t0 = time.monotonic()
                try:
                    send.sendto(pkt, (destination, 0))
                finally:
                    send.close()

                try:
                    raw, addr = recv_sock.recvfrom(65536)
                    rtt_ms = (time.monotonic() - t0) * 1000
                    hop_ip = addr[0]
                    break
                except socket.timeout:
                    continue

            if hop_ip:
                result.hops.append(Hop(ttl=ttl, ip=hop_ip, rtt_ms=round(rtt_ms, 3)))
                if hop_ip == destination:
                    result.reached = True
                    break
    finally:
        recv_sock.close()

    return result


# ── topology builder ──────────────────────────────────────────────────────────

def build_topology(
    local_ip: str,
    hosts: list[str],
    run_traceroute: bool = True,
) -> NetworkGraph:
    """
    Build a NetworkGraph from the local machine to each discovered host.

    If run_traceroute is False, only the local-to-host edges are added
    (useful when raw socket access is unavailable).
    """
    graph = NetworkGraph()
    gw    = default_gateway()

    graph.add_node(local_ip)
    if gw:
        graph.add_node(gw, is_gateway=True, is_router=True)
        graph.add_edge(local_ip, gw)

    for ip in hosts:
        graph.add_node(ip)

        if not run_traceroute:
            graph.add_edge(gw or local_ip, ip)
            continue

        trace = traceroute(ip)
        prev  = local_ip

        for hop in trace.hops:
            if hop.ip == "*":
                continue
            if hop.ip not in (local_ip,):
                graph.add_node(hop.ip, is_router=(hop.ip != ip))
            graph.add_edge(prev, hop.ip, rtt_ms=hop.rtt_ms)
            prev = hop.ip

        if not trace.hops:
            graph.add_edge(gw or local_ip, ip)

    return graph


# ── reverse DNS ───────────────────────────────────────────────────────────────

def resolve_hostnames(graph: NetworkGraph, timeout: float = 0.5) -> None:
    """Attempt reverse DNS lookups for all graph nodes (best-effort)."""
    socket.setdefaulttimeout(timeout)
    for node in graph.nodes.values():
        try:
            name, _, _ = socket.gethostbyaddr(node.ip)
            node.hostname = name
        except (socket.herror, socket.timeout, OSError):
            node.hostname = None
    socket.setdefaulttimeout(None)


def _local_src(dst: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()
