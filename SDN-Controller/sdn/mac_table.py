"""
MAC learning table.

Maintains a per-datapath mapping of MAC address → port number.
Entries age out after a configurable idle timeout (default 300 s).

Thread-safe: a single RLock guards the table.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class MACEntry:
    port:      int
    learned_at: float = 0.0
    last_seen:  float = 0.0
    hits:       int   = 0


class MACTable:
    """
    Per-datapath MAC → port mapping.

    Parameters
    ----------
    idle_timeout : float
        Seconds after last packet before an entry expires.
    """

    def __init__(self, idle_timeout: float = 300.0) -> None:
        self._idle_timeout = idle_timeout
        # _table: dpid → {mac_str: MACEntry}
        self._table: dict[int, dict[str, MACEntry]] = {}
        self._lock  = threading.RLock()

    def learn(self, dpid: int, mac: str, port: int) -> bool:
        """
        Record mac → port for dpid.

        Returns True if this is a new entry or the port changed.
        """
        now = time.monotonic()
        with self._lock:
            dp = self._table.setdefault(dpid, {})
            existing = dp.get(mac)
            if existing and existing.port == port:
                existing.last_seen = now
                existing.hits     += 1
                return False
            dp[mac] = MACEntry(port=port, learned_at=now, last_seen=now)
            return True

    def lookup(self, dpid: int, mac: str) -> Optional[int]:
        """Return the port for mac on dpid, or None if unknown / expired."""
        now = time.monotonic()
        with self._lock:
            entry = self._table.get(dpid, {}).get(mac)
            if entry is None:
                return None
            if now - entry.last_seen > self._idle_timeout:
                del self._table[dpid][mac]
                return None
            entry.last_seen = now
            entry.hits      += 1
            return entry.port

    def remove(self, dpid: int, mac: str) -> None:
        with self._lock:
            self._table.get(dpid, {}).pop(mac, None)

    def clear_dpid(self, dpid: int) -> None:
        with self._lock:
            self._table.pop(dpid, None)

    def expire(self) -> int:
        """Remove all stale entries.  Returns count of removed entries."""
        now     = time.monotonic()
        removed = 0
        with self._lock:
            for dp in self._table.values():
                stale = [m for m, e in dp.items()
                         if now - e.last_seen > self._idle_timeout]
                for m in stale:
                    del dp[m]
                    removed += 1
        return removed

    def snapshot(self, dpid: int) -> dict[str, int]:
        """Return a copy of the MAC table for dpid."""
        with self._lock:
            return {m: e.port for m, e in self._table.get(dpid, {}).items()}

    def all_dpids(self) -> list[int]:
        with self._lock:
            return list(self._table.keys())

    def __repr__(self) -> str:
        with self._lock:
            total = sum(len(v) for v in self._table.values())
            return f"MACTable(dpids={len(self._table)}, entries={total})"
