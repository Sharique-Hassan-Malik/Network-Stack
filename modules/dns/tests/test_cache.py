"""Cache behaviour, with an injected clock.

Every expiry test here is exact. Nothing sleeps: a cache whose tests sleep is a
cache whose boundary conditions are never actually checked, because no one
writes a test that waits 300 seconds to see whether a TTL of 300 expired at the
right moment.
"""

from __future__ import annotations

from dnskit import wire
from dnskit.cache import Cache


def rec(name: str, ttl: int, value: str = "1.2.3.4") -> wire.Record:
    octets = bytes(int(p) for p in value.split("."))
    return wire.Record(name, wire.TYPE_A, wire.CLASS_IN, ttl, octets, value)


def test_a_stored_answer_is_returned_before_it_expires():
    c = Cache()
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 300),), now=1000.0)
    assert c.get("example.com", wire.TYPE_A, now=1299.0) is not None


def test_an_answer_expires_exactly_at_its_ttl():
    c = Cache()
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 300),), now=1000.0)
    assert c.get("example.com", wire.TYPE_A, now=1299.999) is not None
    assert c.get("example.com", wire.TYPE_A, now=1300.0) is None


def test_lookup_is_case_insensitive():
    c = Cache()
    c.put("Example.COM", wire.TYPE_A, (rec("example.com.", 300),), now=0.0)
    assert c.get("eXaMpLe.com.", wire.TYPE_A, now=1.0) is not None


def test_a_different_type_is_a_different_entry():
    c = Cache()
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 300),), now=0.0)
    assert c.get("example.com", wire.TYPE_AAAA, now=1.0) is None


def test_an_rrset_expires_on_its_shortest_ttl():
    """The set's TTL is the minimum across it, not each record's own.

    Per-record expiry lets a set decay into a partial answer, and a partial
    answer is worse than none: it looks complete, so nothing re-queries.
    """
    c = Cache()
    c.put("example.com", wire.TYPE_A,
          (rec("example.com.", 600, "1.1.1.1"), rec("example.com.", 60, "2.2.2.2")),
          now=0.0)
    assert c.get("example.com", wire.TYPE_A, now=59.0) is not None
    assert c.get("example.com", wire.TYPE_A, now=61.0) is None


def test_a_ttl_of_zero_is_not_cached():
    c = Cache()
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 0),), now=0.0)
    assert c.get("example.com", wire.TYPE_A, now=0.0) is None


def test_an_absurd_ttl_is_capped():
    """A TTL of weeks pins a stale answer past any plausible change window."""
    c = Cache(max_ttl=3600.0)
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 30 * 86400),), now=0.0)
    assert c.get("example.com", wire.TYPE_A, now=3599.0) is not None
    assert c.get("example.com", wire.TYPE_A, now=3601.0) is None


def test_a_negative_answer_is_cached():
    """RFC 2308. Without this, a typo re-queries the root on every retry."""
    c = Cache()
    c.put("nope.example.com", wire.TYPE_A, (), now=0.0,
          rcode=wire.RCODE_NXDOMAIN, ttl_override=120.0)
    assert c.get("nope.example.com", wire.TYPE_A, now=60.0) == ()
    assert c.get("nope.example.com", wire.TYPE_A, now=121.0) is None


def test_eviction_drops_the_entry_closest_to_expiry():
    c = Cache(max_entries=2)
    c.put("soon.test", wire.TYPE_A, (rec("soon.test.", 10),), now=0.0)
    c.put("later.test", wire.TYPE_A, (rec("later.test.", 1000),), now=0.0)
    c.put("new.test", wire.TYPE_A, (rec("new.test.", 500),), now=0.0)

    assert len(c) == 2
    assert c.get("soon.test", wire.TYPE_A, now=1.0) is None, "the soonest to expire goes first"
    assert c.get("later.test", wire.TYPE_A, now=1.0) is not None


def test_statistics_count_hits_misses_and_expiries():
    c = Cache()
    c.put("example.com", wire.TYPE_A, (rec("example.com.", 10),), now=0.0)
    c.get("example.com", wire.TYPE_A, now=1.0)      # hit
    c.get("other.com", wire.TYPE_A, now=1.0)        # miss
    c.get("example.com", wire.TYPE_A, now=100.0)    # expired -> miss

    stats = c.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 2
    assert stats["expired"] == 1
    assert 0.0 < stats["hit_rate"] < 1.0


def test_purging_removes_only_what_has_expired():
    c = Cache()
    c.put("a.test", wire.TYPE_A, (rec("a.test.", 10),), now=0.0)
    c.put("b.test", wire.TYPE_A, (rec("b.test.", 1000),), now=0.0)
    assert c.purge_expired(now=50.0) == 1
    assert len(c) == 1
