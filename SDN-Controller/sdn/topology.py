"""
Network topology graph.

Maintains a view of the network derived from:
  - FEATURES_REPLY (switch ports)
  - LLDP-based link discovery (which port on switch A connects to which port
    on switch B — implemented in the discovery module)
  - PACKET_IN events that reveal host locations

Provides:
  - Dijkstra shortest-path between any two hosts
  - Spanning-tree computation (Prim's algorithm) used to prevent loops
    on broadcast traffic
"""

from __future__ import annotations

import heapq
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Link:
    src_dpid: int
    src_port: int
    dst_dpid: int
    dst_port: int


@dataclass
class HostLocation:
    dpid:     int
    port:     int
    ip:       Optional[str] = None


@dataclass
class SwitchInfo:
    dpid:  int
    ports: set[int] = field(default_factory=set)


class TopologyGraph:
    """
    Thread-safe topology graph.

    Nodes are datapath IDs (64-bit integers).
    Edges are inter-switch links discovered by LLDP.
    Host locations map MAC → (dpid, port).
    """

    def __init__(self) -> None:
        self._switches: dict[int, SwitchInfo]      = {}
        self._links:    set[Link]                   = set()
        self._hosts:    dict[str, HostLocation]     = {}
        self._lock      = threading.RLock()

    # ── mutation ──────────────────────────────────────────────────────────────

    def add_switch(self, dpid: int, ports: set[int] | None = None) -> None:
        with self._lock:
            if dpid not in self._switches:
                self._switches[dpid] = SwitchInfo(dpid=dpid, ports=ports or set())
            elif ports:
                self._switches[dpid].ports.update(ports)

    def remove_switch(self, dpid: int) -> None:
        with self._lock:
            self._switches.pop(dpid, None)
            self._links = {l for l in self._links
                           if l.src_dpid != dpid and l.dst_dpid != dpid}

    def add_link(self, src_dpid: int, src_port: int, dst_dpid: int, dst_port: int) -> None:
        with self._lock:
            self._links.add(Link(src_dpid, src_port, dst_dpid, dst_port))
            self._links.add(Link(dst_dpid, dst_port, src_dpid, src_port))

    def remove_link(self, src_dpid: int, src_port: int) -> None:
        with self._lock:
            # Remove both directions of the link that uses this port
            to_remove = {l for l in self._links
                         if l.src_dpid == src_dpid and l.src_port == src_port}
            reverse   = {Link(l.dst_dpid, l.dst_port, l.src_dpid, l.src_port)
                         for l in to_remove}
            self._links -= to_remove | reverse

    def update_host(self, mac: str, dpid: int, port: int, ip: str | None = None) -> None:
        with self._lock:
            self._hosts[mac] = HostLocation(dpid=dpid, port=port, ip=ip)

    def remove_host(self, mac: str) -> None:
        with self._lock:
            self._hosts.pop(mac, None)

    # ── query ─────────────────────────────────────────────────────────────────

    def host_location(self, mac: str) -> Optional[HostLocation]:
        with self._lock:
            return self._hosts.get(mac)

    def switch_ports(self, dpid: int) -> set[int]:
        with self._lock:
            sw = self._switches.get(dpid)
            return set(sw.ports) if sw else set()

    def neighbours(self, dpid: int) -> list[tuple[int, int, int]]:
        """Return [(dst_dpid, src_port, dst_port)] for all links from dpid."""
        with self._lock:
            return [
                (l.dst_dpid, l.src_port, l.dst_port)
                for l in self._links if l.src_dpid == dpid
            ]

    def link_port(self, src_dpid: int, dst_dpid: int) -> Optional[tuple[int, int]]:
        """Return (src_port, dst_port) of the link between two switches, or None."""
        with self._lock:
            for l in self._links:
                if l.src_dpid == src_dpid and l.dst_dpid == dst_dpid:
                    return l.src_port, l.dst_port
        return None

    def all_switches(self) -> list[int]:
        with self._lock:
            return list(self._switches.keys())

    def all_hosts(self) -> dict[str, HostLocation]:
        with self._lock:
            return dict(self._hosts)

    def is_inter_switch_port(self, dpid: int, port: int) -> bool:
        """True if port is connected to another switch (not a host edge port)."""
        with self._lock:
            return any(l.src_dpid == dpid and l.src_port == port for l in self._links)

    # ── path computation ──────────────────────────────────────────────────────

    def shortest_path(self, src_dpid: int, dst_dpid: int) -> list[int]:
        """
        Dijkstra shortest path (hop count).

        Returns list of DPIDs from src to dst inclusive, or [] if unreachable.
        """
        if src_dpid == dst_dpid:
            return [src_dpid]

        with self._lock:
            nodes = set(self._switches.keys())
            adj: dict[int, list[int]] = {n: [] for n in nodes}
            for l in self._links:
                adj[l.src_dpid].append(l.dst_dpid)

        dist   = {n: float("inf") for n in nodes}
        prev:  dict[int, Optional[int]] = {n: None for n in nodes}
        dist[src_dpid] = 0
        heap   = [(0, src_dpid)]

        while heap:
            d, u = heapq.heappop(heap)
            if d > dist[u]:
                continue
            if u == dst_dpid:
                break
            for v in adj.get(u, []):
                nd = d + 1
                if nd < dist[v]:
                    dist[v]  = nd
                    prev[v]  = u
                    heapq.heappush(heap, (nd, v))

        if dist[dst_dpid] == float("inf"):
            return []

        path = []
        cur  = dst_dpid
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return path

    def spanning_tree_ports(self) -> dict[int, set[int]]:
        """
        Compute a spanning tree (Prim's algorithm).

        Returns dict[dpid → set of ports that are ON the spanning tree].
        Only links that are part of the spanning tree are in the set.
        Ports not in the set should have broadcast traffic dropped.
        """
        with self._lock:
            nodes = set(self._switches.keys())
            if not nodes:
                return {}
            root   = next(iter(nodes))
            in_tree: set[int] = {root}
            tree_ports: dict[int, set[int]] = {n: set() for n in nodes}
            heap: list[tuple[int, int, int, int]] = []   # (cost, src, src_port, dst)

            for dst, src_port, _ in self.neighbours(root):
                heapq.heappush(heap, (1, root, src_port, dst))

            while heap and len(in_tree) < len(nodes):
                _, src, src_port, dst = heapq.heappop(heap)
                if dst in in_tree:
                    continue
                in_tree.add(dst)
                # Find the corresponding dst_port
                result = self.link_port(src, dst)
                if result:
                    tree_ports[src].add(src_port)
                    tree_ports[dst].add(result[1])
                for d2, p2, _ in self.neighbours(dst):
                    if d2 not in in_tree:
                        heapq.heappush(heap, (1, dst, p2, d2))

        return tree_ports

    def to_dict(self) -> dict:
        """Serialisable snapshot for REST API."""
        with self._lock:
            return {
                "switches": [
                    {"dpid": f"0x{dpid:016x}", "ports": sorted(sw.ports)}
                    for dpid, sw in self._switches.items()
                ],
                "links": [
                    {
                        "src": f"0x{l.src_dpid:016x}", "src_port": l.src_port,
                        "dst": f"0x{l.dst_dpid:016x}", "dst_port": l.dst_port,
                    }
                    for l in self._links if l.src_dpid < l.dst_dpid
                ],
                "hosts": [
                    {"mac": mac, "dpid": f"0x{h.dpid:016x}",
                     "port": h.port, "ip": h.ip}
                    for mac, h in self._hosts.items()
                ],
            }
