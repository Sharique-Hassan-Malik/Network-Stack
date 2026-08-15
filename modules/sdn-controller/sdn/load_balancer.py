"""
SDN load balancer.

The controller intercepts TCP SYN packets destined for a virtual IP (VIP)
and rewrites the destination to a backend server chosen by the current policy.
Subsequent packets in the same flow use the same backend (connection affinity)
tracked in a flow table keyed on (client_ip, client_port).

Two scheduling policies are provided:
  round_robin    — backends selected in rotation
  least_conn     — backend with fewest active flows selected

When a backend is removed from the pool, all flows mapped to it are
evicted so they will be re-matched on the next packet.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Policy(Enum):
    ROUND_ROBIN  = "round_robin"
    LEAST_CONN   = "least_conn"


@dataclass
class Backend:
    ip:      str
    port:    int
    mac:     str
    weight:  int   = 1
    active:  bool  = True
    _conns:  int   = field(default=0, repr=False)

    @property
    def connections(self) -> int:
        return self._conns


@dataclass
class FlowEntry:
    client_ip:   str
    client_port: int
    backend:     Backend
    created_at:  float = field(default_factory=time.monotonic)
    last_seen:   float = field(default_factory=time.monotonic)


class LoadBalancer:
    """
    Virtual-IP load balancer.

    Parameters
    ----------
    vip : str
        The virtual IP clients connect to.
    vport : int
        The virtual TCP port.
    policy : Policy
        Scheduling algorithm.
    flow_timeout : float
        Seconds of inactivity before a flow mapping expires.
    """

    def __init__(
        self,
        vip:          str,
        vport:        int,
        policy:       Policy       = Policy.ROUND_ROBIN,
        flow_timeout: float        = 300.0,
    ) -> None:
        self.vip          = vip
        self.vport        = vport
        self.policy       = policy
        self.flow_timeout = flow_timeout

        self._backends:   list[Backend]                    = []
        self._flows:      dict[tuple, FlowEntry]           = {}
        self._rr_index:   int                              = 0
        self._lock        = threading.RLock()

    # ── backend management ────────────────────────────────────────────────────

    def add_backend(self, ip: str, port: int, mac: str, weight: int = 1) -> Backend:
        with self._lock:
            for b in self._backends:
                if b.ip == ip and b.port == port:
                    b.active = True
                    return b
            b = Backend(ip=ip, port=port, mac=mac, weight=weight)
            self._backends.append(b)
            return b

    def remove_backend(self, ip: str, port: int) -> None:
        with self._lock:
            self._backends = [b for b in self._backends
                              if not (b.ip == ip and b.port == port)]
            # Evict all flows that used this backend
            self._flows = {k: v for k, v in self._flows.items()
                           if not (v.backend.ip == ip and v.backend.port == port)}

    def set_backend_active(self, ip: str, port: int, active: bool) -> None:
        with self._lock:
            for b in self._backends:
                if b.ip == ip and b.port == port:
                    b.active = active
                    if not active:
                        # Evict flows to this backend so they are rerouted
                        self._flows = {k: v for k, v in self._flows.items()
                                       if v.backend is not b}
                    return

    def active_backends(self) -> list[Backend]:
        with self._lock:
            return [b for b in self._backends if b.active]

    # ── flow mapping ──────────────────────────────────────────────────────────

    def get_backend(self, client_ip: str, client_port: int) -> Optional[Backend]:
        """
        Return the backend for this client flow, creating a new mapping if needed.
        Returns None when no active backends are available.
        """
        key = (client_ip, client_port)
        now = time.monotonic()

        with self._lock:
            entry = self._flows.get(key)
            if entry is not None:
                if now - entry.last_seen < self.flow_timeout and entry.backend.active:
                    entry.last_seen = now
                    return entry.backend
                # Expired or backend went down
                entry.backend._conns -= 1
                del self._flows[key]

            backend = self._select()
            if backend is None:
                return None

            backend._conns += 1
            self._flows[key] = FlowEntry(
                client_ip=client_ip, client_port=client_port,
                backend=backend,
            )
            return backend

    def release_flow(self, client_ip: str, client_port: int) -> None:
        """Mark a flow as completed (TCP FIN / RST observed)."""
        key = (client_ip, client_port)
        with self._lock:
            entry = self._flows.pop(key, None)
            if entry:
                entry.backend._conns = max(0, entry.backend._conns - 1)

    def expire_flows(self) -> int:
        """Remove idle flows.  Returns count removed."""
        now = time.monotonic()
        with self._lock:
            stale = [k for k, v in self._flows.items()
                     if now - v.last_seen > self.flow_timeout]
            for k in stale:
                self._flows[k].backend._conns -= 1
                del self._flows[k]
        return len(stale)

    # ── selection ─────────────────────────────────────────────────────────────

    def _select(self) -> Optional[Backend]:
        active = [b for b in self._backends if b.active]
        if not active:
            return None
        if self.policy == Policy.ROUND_ROBIN:
            return self._round_robin(active)
        return self._least_conn(active)

    def _round_robin(self, active: list[Backend]) -> Backend:
        weighted: list[Backend] = []
        for b in active:
            weighted.extend([b] * b.weight)
        b = weighted[self._rr_index % len(weighted)]
        self._rr_index = (self._rr_index + 1) % len(weighted)
        return b

    def _least_conn(self, active: list[Backend]) -> Backend:
        return min(active, key=lambda b: b._conns / b.weight)

    # ── stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            return {
                "vip":      self.vip,
                "vport":    self.vport,
                "policy":   self.policy.value,
                "flows":    len(self._flows),
                "backends": [
                    {
                        "ip":          b.ip,
                        "port":        b.port,
                        "active":      b.active,
                        "connections": b._conns,
                        "weight":      b.weight,
                    }
                    for b in self._backends
                ],
            }
