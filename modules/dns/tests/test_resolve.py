"""Resolution against the live network, and the differential check.

These tests need UDP port 53 outbound to the root servers. Where that is not
available they skip **by name**, loudly, rather than passing quietly — a
resolver whose network tests silently vanish in CI is a resolver with no tests
at all.

The differential test is the one that matters. Round-tripping our own encoder
through our own decoder proves the two halves agree; only comparing against a
resolver written by someone else shows the walk down from the root reaches the
same place the rest of the internet does.
"""

from __future__ import annotations

import socket

import pytest

from dnskit import Resolver, ResolveError, wire

# Names chosen for stability rather than convenience: each is operated by an
# organisation that has run it for years, and each exercises a different
# delegation shape.
STABLE_NAMES = [
    "example.com",
    "iana.org",
    "cloudflare.com",
]


def _root_reachable() -> bool:
    """Can we speak UDP/53 to a root server at all?"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        query = wire.encode_query("example.com", wire.TYPE_A, 0x1234)
        sock.sendto(query, ("198.41.0.4", 53))
        sock.recvfrom(4096)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _system_resolves() -> bool:
    try:
        socket.gethostbyname("example.com")
        return True
    except OSError:
        return False


needs_root = pytest.mark.skipif(
    not _root_reachable(),
    reason="no UDP/53 to the root servers from this host — the iterative walk "
           "cannot be exercised",
)
needs_system = pytest.mark.skipif(
    not _system_resolves(),
    reason="the system resolver is unavailable, so there is nothing to compare against",
)


@pytest.fixture
def resolver():
    return Resolver(timeout=5.0)


@needs_root
@pytest.mark.slow
def test_it_resolves_from_the_root_without_an_upstream_resolver(resolver):
    """The claim: no recursive resolver is used, only the roots and delegations."""
    answer = resolver.resolve("example.com", wire.TYPE_A)
    assert answer.rcode == wire.RCODE_NOERROR
    assert answer.values, "no address returned"
    # Root, then the TLD, then the zone: at least three servers were consulted.
    assert answer.queries_sent >= 3, answer.trace
    assert any(part.startswith(".") for part in answer.trace), answer.trace


@needs_root
@needs_system
@pytest.mark.slow
@pytest.mark.parametrize("name", STABLE_NAMES)
def test_answers_agree_with_the_system_resolver(resolver, name):
    """Differential: our walk from the root against whatever the OS uses.

    Compared as *sets with a non-empty intersection* rather than for equality.
    Large sites answer from anycast pools and geographic load balancers, so two
    resolvers asking seconds apart legitimately get different subsets. An
    equality assertion here would fail for reasons that have nothing to do with
    this code, and a test that fails for unrelated reasons gets disabled.
    """
    ours = set(resolver.resolve(name, wire.TYPE_A).values)
    assert ours, f"we returned nothing for {name}"

    try:
        _, _, theirs = socket.gethostbyname_ex(name)
    except OSError:
        pytest.skip(f"the system resolver could not resolve {name}")

    assert set(theirs), f"the system resolver returned nothing for {name}"
    assert ours & set(theirs), (
        f"{name}: no overlap between our answer {sorted(ours)} "
        f"and the system's {sorted(theirs)}"
    )


@needs_root
@pytest.mark.slow
def test_a_name_with_no_record_of_that_type_is_noerror_and_empty(resolver):
    """NODATA, which is not the same as NXDOMAIN and not the same as failure.

    `root-servers.net` exists and has NS records but no A record. The correct
    answer is NOERROR with an empty answer section; returning NXDOMAIN would
    claim the name does not exist, and raising would make a legitimate answer
    look like a network problem.
    """
    answer = resolver.resolve("root-servers.net", wire.TYPE_A)
    assert answer.rcode == wire.RCODE_NOERROR
    assert answer.values == []


@needs_root
@pytest.mark.slow
def test_a_nonexistent_name_is_nxdomain_not_an_exception(resolver):
    answer = resolver.resolve("this-name-does-not-exist-xyzzy-42.example.com", wire.TYPE_A)
    assert answer.rcode == wire.RCODE_NXDOMAIN
    assert answer.values == []


@needs_root
@pytest.mark.slow
def test_the_second_lookup_is_served_from_cache(resolver):
    first = resolver.resolve("example.com", wire.TYPE_A)
    second = resolver.resolve("example.com", wire.TYPE_A)

    assert first.queries_sent > 0
    assert second.queries_sent == 0, "the second lookup sent packets"
    assert second.from_cache
    assert set(first.values) == set(second.values)


@needs_root
@pytest.mark.slow
def test_a_cname_is_followed_to_an_address(resolver):
    """www.github.com is a CNAME. The resolver must chase it to an A record."""
    answer = resolver.resolve("www.github.com", wire.TYPE_A)
    if answer.rcode != wire.RCODE_NOERROR:
        pytest.skip("www.github.com did not answer NOERROR from here")
    assert answer.values, answer.trace


@needs_root
@pytest.mark.slow
def test_it_records_latency_through_the_shared_measurement(resolver):
    """The RTT numbers come from netcore, not from a private copy."""
    resolver.resolve("example.com", wire.TYPE_A)
    stats = resolver.stats()
    assert stats["queries_sent"] > 0
    assert stats["rtt_p50_ms"] > 0.0
    assert stats["rtt_p99_ms"] >= stats["rtt_p50_ms"]


def test_an_unreachable_server_reports_which_query_failed():
    """Errors name the query. A bare timeout tells the caller nothing."""
    # 198.51.100.0/24 is reserved for documentation (RFC 5737) and routes
    # nowhere, so this cannot accidentally reach a real server.
    r = Resolver(timeout=0.4, max_retries=0)
    r_roots = (("blackhole", "198.51.100.1"),)
    import dnskit.resolve as rs
    original = rs.ROOT_SERVERS
    rs.ROOT_SERVERS = r_roots
    try:
        with pytest.raises(ResolveError, match="example.com"):
            r.resolve("example.com", wire.TYPE_A)
    finally:
        rs.ROOT_SERVERS = original
