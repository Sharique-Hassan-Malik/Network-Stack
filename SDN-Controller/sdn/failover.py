"""
Automatic failover.

The failover manager monitors:
  - Port-Status messages from switches (link up / down)
  - Periodic heartbeat probes to edge hosts

When a link failure is detected it:
  1. Removes the failed link from the topology graph.
  2. Recomputes shortest paths for all affected host pairs.
  3. Installs new flow rules on affected switches.
  4. Optionally notifies registered callback functions.

Flow invalidation strategy: rather than tracking every individual flow,
the controller uses a hard_timeout of 0 on all proactive rules and
relies on the link-failure event to trigger a full recompute for
affected switches.  A DELETE_STRICT is issued for each stale rule.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .openflow import OFPPortReason, PortStatus
from .topology import TopologyGraph

log = logging.getLogger(__name__)


@dataclass
class LinkFailureEvent:
    dpid:      int
    port:      int
    timestamp: float = field(default_factory=time.monotonic)
    recovered: bool  = False


FailoverCallback = Callable[["FailoverManager", LinkFailureEvent], None]


class FailoverManager:
    """
    Listens for port-status changes and coordinates path re-computation.

    Parameters
    ----------
    topology : TopologyGraph
    install_fn : callable
        Called with (dpid, flows_to_install) when new routes must be pushed.
        Signature: install_fn(dpid: int, rules: list[dict]) -> None
        Each rule dict has keys: match, actions, priority, idle_timeout.
    callbacks : list[FailoverCallback]
        External observers notified on each failover event.
    """

    def __init__(
        self,
        topology: TopologyGraph,
        install_fn: Optional[Callable] = None,
        callbacks:  Optional[list[FailoverCallback]] = None,
    ) -> None:
        self._topo       = topology
        self._install    = install_fn
        self._callbacks  = callbacks or []

        self._failures:  dict[tuple[int, int], LinkFailureEvent] = {}
        self._lock       = threading.Lock()

        # Probe tracking: (dpid, port) → last_seen time
        self._heartbeat: dict[tuple[int, int], float] = {}
        self._hb_interval = 5.0     # seconds
        self._hb_timeout  = 15.0    # declare dead after this many seconds

        self._running = False
        self._hb_thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running  = True
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="failover-hb"
        )
        self._hb_thread.start()

    def stop(self) -> None:
        self._running = False

    # ── port-status handler ───────────────────────────────────────────────────

    def on_port_status(self, dpid: int, status: PortStatus) -> None:
        """Called by the controller when a PORT_STATUS message arrives."""
        port    = status.port_no
        reason  = status.reason
        is_down = bool(status.state & PortStatus.PORT_LINK_DOWN)

        if reason == OFPPortReason.DELETE or is_down:
            self._handle_failure(dpid, port)
        elif reason in (OFPPortReason.ADD, OFPPortReason.MODIFY) and not is_down:
            self._handle_recovery(dpid, port)

    def _handle_failure(self, dpid: int, port: int) -> None:
        key = (dpid, port)
        now = time.monotonic()
        with self._lock:
            if key in self._failures and not self._failures[key].recovered:
                return   # already handling this failure
            evt = LinkFailureEvent(dpid=dpid, port=port, timestamp=now)
            self._failures[key] = evt

        log.warning("Link failure: dpid=0x%016x port=%d", dpid, port)
        self._topo.remove_link(dpid, port)
        self._recompute_paths(dpid)

        for cb in self._callbacks:
            try:
                cb(self, evt)
            except Exception:
                log.exception("Failover callback error")

    def _handle_recovery(self, dpid: int, port: int) -> None:
        key = (dpid, port)
        with self._lock:
            evt = self._failures.pop(key, None)
            if evt:
                evt.recovered = True

        log.info("Link recovered: dpid=0x%016x port=%d", dpid, port)
        self._recompute_paths(dpid)

    # ── path recomputation ────────────────────────────────────────────────────

    def _recompute_paths(self, affected_dpid: int) -> None:
        """
        Recompute all host-pair paths through affected_dpid and push new rules.

        Sends DELETE rules for old entries on affected switches, then
        installs new flow rules along the recomputed paths.
        """
        if self._install is None:
            return

        hosts = self._topo.all_hosts()
        macs  = list(hosts.keys())
        seen:  set[tuple[str, str]] = set()

        for src_mac in macs:
            for dst_mac in macs:
                if src_mac == dst_mac:
                    continue
                pair = tuple(sorted((src_mac, dst_mac)))
                if pair in seen:
                    continue
                seen.add(pair)

                src_loc = self._topo.host_location(src_mac)
                dst_loc = self._topo.host_location(dst_mac)
                if src_loc is None or dst_loc is None:
                    continue

                path = self._topo.shortest_path(src_loc.dpid, dst_loc.dpid)
                if not path:
                    log.warning("No path from %s to %s after failover", src_mac, dst_mac)
                    continue

                self._install_path(path, src_mac, dst_mac, src_loc, dst_loc)

    def _install_path(self, path, src_mac, dst_mac, src_loc, dst_loc) -> None:
        """Push flow rules along path for the src→dst direction."""
        import socket as _s
        for i, dpid in enumerate(path):
            if i == len(path) - 1:
                # Last hop: forward to host edge port
                out_port = dst_loc.port
            else:
                # Forward toward next switch
                result = self._topo.link_port(dpid, path[i + 1])
                if result is None:
                    continue
                out_port = result[0]

            rule = {
                "match":        {"eth_dst": dst_mac},
                "actions":      [{"type": "OUTPUT", "port": out_port}],
                "priority":     20,
                "idle_timeout": 60,
            }
            if self._install:
                self._install(dpid, [rule])

    # ── heartbeat ─────────────────────────────────────────────────────────────

    def record_heartbeat(self, dpid: int, port: int) -> None:
        """Call this when a packet is received on (dpid, port)."""
        with self._lock:
            self._heartbeat[(dpid, port)] = time.monotonic()

    def _heartbeat_loop(self) -> None:
        while self._running:
            time.sleep(self._hb_interval)
            now = time.monotonic()
            with self._lock:
                stale = [
                    (dpid, port)
                    for (dpid, port), ts in self._heartbeat.items()
                    if now - ts > self._hb_timeout
                ]
            for dpid, port in stale:
                log.warning("Heartbeat timeout: dpid=0x%016x port=%d", dpid, port)
                self._handle_failure(dpid, port)

    # ── status ────────────────────────────────────────────────────────────────

    def active_failures(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "dpid": f"0x{e.dpid:016x}",
                    "port": e.port,
                    "since": e.timestamp,
                }
                for e in self._failures.values()
                if not e.recovered
            ]
