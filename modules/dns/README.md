# DNS Resolver

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; `net` shares its RTT estimator and measurement types with the QUIC
> and transport modules.

An **iterative** DNS resolver: it starts at a root server and walks the
delegation chain down, rather than asking a recursive resolver to do the work.
Standard library only.

```
$ python tools/resolve.py --trace example.com

  . via l.root-servers.net (199.7.83.42)
  com. via g.gtld-servers.net. (192.42.93.30)
  example.com. via elliott.ns.cloudflare.com. (172.64.35.228)

  example.com. 300 A 104.20.23.154
  example.com. 300 A 172.66.147.243

  3 queries in 410 ms
```

## Iterative, and why that is the whole point

Asking `8.8.8.8` for a name is one UDP exchange. It teaches nothing, because
the interesting work — following delegations, choosing servers, honouring TTLs,
handling referrals without glue — happens on someone else's machine.

This does that work. The trace above is the actual protocol: the root knows
only where `com` lives, the `com` servers know only where `example.com` lives,
and Cloudflare's servers answer authoritatively. Three questions, three
different servers, no recursive resolver involved at any point.

The 13 root server addresses are hardcoded, because they must be. There is
nothing to resolve their names with yet; that bootstrap is where the whole
system hangs from.

## Verified against a resolver written by someone else

```
$ pytest -m slow

tests/test_resolve.py::test_answers_agree_with_the_system_resolver[example.com]    PASSED
tests/test_resolve.py::test_answers_agree_with_the_system_resolver[iana.org]       PASSED
tests/test_resolve.py::test_answers_agree_with_the_system_resolver[cloudflare.com] PASSED
```

Round-tripping our own encoder through our own decoder proves the two halves
agree with each other, which they would even if both were wrong. The
differential test compares our walk from the root against whatever the
operating system uses, on names that have been stable for years.

It compares as **sets with a non-empty intersection**, not for equality: large
sites answer from anycast pools and geographic load balancers, so two resolvers
asking seconds apart legitimately get different subsets. An equality assertion
would fail for reasons unrelated to this code, and a test that fails for
unrelated reasons is a test that gets switched off.

Where the network is unavailable those tests **skip by name**, loudly. A
resolver whose network tests quietly vanish in CI is a resolver with no tests.

## What is shared with the rest of the stack

Two things come from [`netcore`](../../netcore), not from a private copy:

- **`RTTEstimator`** (RFC 6298), one per server. A resolver talks to servers
  with wildly different latency — a root server two hops away and an
  authoritative server on another continent — and giving both the same fixed
  timeout means either giving up too early on one or waiting too long on the
  other. This is the same problem QUIC and the transport module solve, with the
  same estimator.
- **`Measurement`**, so query latency is reported with the same percentile
  definition as every other measurement in the repository. `net`'s percentiles
  interpolate; a private implementation using index arithmetic would report a
  different p99 for the same samples.

## Layout

```
dnskit/wire.py      message encoding and decoding — pure, no I/O
dnskit/cache.py     TTL-honouring cache — pure, clock injected
dnskit/resolve.py   the iterative walk: sockets, retries, delegation
tools/resolve.py    the command line
tests/              39 tests; the network ones are marked `slow`
```

`wire` and `cache` have no sockets and no clock, which is what lets the parser
be fuzzed at full speed and lets TTL expiry be tested at the exact boundary
rather than by sleeping.

## The parsing is defensive, deliberately

A resolver parses packets from servers it has never met, and some of them are
hostile. Three checks are not optional and each has a test:

- **Compression pointers must point strictly backwards.** A pointer to itself
  is four bytes that hang a naive parser forever, and a pair of forward
  pointers is the same loop written differently.
- **The decoded name length is capped at 255 bytes** even when every pointer is
  legal. A chain of valid backward pointers can describe a name of unbounded
  length, so the loop check alone does not bound the work.
- **TTLs are read unsigned.** Parsing a TTL above 2³¹ as signed makes it
  negative, so the record is treated as permanently stale — a cache that fails
  to cache exactly the records a zone wanted cached longest.

## Cache behaviour

- An RRset expires on its **shortest** TTL, not per record. Per-record expiry
  lets a set decay into a partial answer, which is worse than none because it
  looks complete.
- **Negative answers are cached** (RFC 2308), bounded by the SOA minimum.
  Without it a typo re-queries the root on every retry.
- TTLs are clamped to a maximum of one day. Authoritative servers occasionally
  publish TTLs of weeks, which pins a stale answer past any plausible change
  window.
- Eviction drops the entry **closest to expiry**, not the least recently used.
  A DNS record carries its own deadline; recency says nothing about whether an
  answer is still true.

## Not implemented

- **No DNSSEC validation.** Signatures are not checked, so this trusts the
  network path. That is a real limitation and the reason this is a study of the
  resolution algorithm rather than something to put in front of users.
- **No TCP fallback.** A truncated reply (`TC=1`) is used as-is rather than
  retried over TCP, so a very large RRset may come back short. EDNS0 would be
  the first fix and is also absent.
- **No 0x20 encoding.** The wire format preserves case, so it could be added;
  the query identifier is randomised per attempt, which is the weaker half of
  the same defence.
- **IPv4 transport only.** The resolver speaks to servers over IPv4 even when
  querying for AAAA records.

## Running it alone

```bash
python tools/resolve.py example.com
python tools/resolve.py --type MX iana.org
pytest                # everything, including the live-network tests
pytest -m "not slow"  # just the pure wire and cache tests
```
