"""A TTL-honouring DNS cache.

Pure: the clock is injected, so expiry can be tested exactly rather than by
sleeping. A cache tested with `time.sleep` is a cache whose test suite takes
minutes and still cannot check the boundary.

Two rules that are easy to get wrong and are enforced here:

  - **The TTL of an RRset is the minimum across its records.** Caching each
    record for its own TTL lets a set decay into a partial answer, which is
    worse than no answer because it looks complete.
  - **Negative answers are cached too**, bounded by the SOA minimum (RFC 2308).
    Without this, a typo in a hostname sends a query to the root on every
    retry, which is exactly the traffic the root servers ask resolvers not to
    send.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .wire import Record, normalise


@dataclass
class _Entry:
    records: tuple[Record, ...]
    expires_at: float
    rcode: int


@dataclass
class Cache:
    """Keyed by (normalised name, type). Bounded by entry count."""

    max_entries: int = 10_000
    #: Ceiling on any TTL. Authoritative servers occasionally publish a TTL of
    #: weeks, which pins a stale answer past any plausible change window.
    max_ttl: float = 86_400.0
    #: Floor, so a TTL of 0 does not mean "query again for every packet".
    min_ttl: float = 0.0

    _entries: dict[tuple[str, int], _Entry] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0
    expired: int = 0

    def get(self, name: str, rtype: int, now: float) -> tuple[Record, ...] | None:
        key = (normalise(name), rtype)
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        if entry.expires_at <= now:
            # Dropped rather than served stale. Serving expired data is a
            # deliberate feature in some resolvers, and it is a different
            # promise from the one this makes.
            del self._entries[key]
            self.expired += 1
            self.misses += 1
            return None
        self.hits += 1
        return entry.records

    def put(self, name: str, rtype: int, records: tuple[Record, ...],
            now: float, *, rcode: int = 0, ttl_override: float | None = None) -> None:
        if not records and ttl_override is None:
            return
        if ttl_override is not None:
            ttl = ttl_override
        else:
            ttl = float(min(r.ttl for r in records))
        ttl = max(self.min_ttl, min(self.max_ttl, ttl))
        if ttl <= 0:
            return

        if len(self._entries) >= self.max_entries:
            self._evict_one(now)
        self._entries[(normalise(name), rtype)] = _Entry(tuple(records), now + ttl, rcode)

    def _evict_one(self, now: float) -> None:
        """Drop the entry closest to expiry.

        Not LRU. A DNS entry has a deadline the data itself specifies, so the
        one expiring soonest is the cheapest to lose and the most likely to be
        wrong already — recency says nothing about whether an answer is still
        true.
        """
        if not self._entries:
            return
        victim = min(self._entries, key=lambda k: self._entries[k].expires_at)
        del self._entries[victim]

    def purge_expired(self, now: float) -> int:
        dead = [k for k, e in self._entries.items() if e.expires_at <= now]
        for k in dead:
            del self._entries[k]
        self.expired += len(dead)
        return len(dead)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def stats(self) -> dict[str, float]:
        return {
            "entries": float(len(self._entries)),
            "hits": float(self.hits),
            "misses": float(self.misses),
            "expired": float(self.expired),
            "hit_rate": self.hit_rate,
        }
