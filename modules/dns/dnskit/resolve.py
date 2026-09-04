"""Iterative resolution, from the root down.

This is the impure layer: sockets, the clock, randomness. Everything it decides
is in `wire` and `cache`, which have none of those.

"Iterative" is the distinction that matters. Asking `8.8.8.8` for a name is one
UDP exchange and teaches nothing — the recursion happens on someone else's
machine. This starts at a root server, is told where `com` lives, asks that
server, is told where `example.com` lives, and continues until something answers
authoritatively. That walk is the protocol.

The RTT estimator and the latency statistics come from `netcore`, shared with
the QUIC and transport modules: a timeout that adapts to the server actually
being talked to is the same problem in all three, and RFC 6298's estimator is
the same answer.
"""

from __future__ import annotations

import random
import secrets
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .cache import Cache
from .wire import (
    CLASS_IN, RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA, TYPE_CNAME,
    TYPE_NS, TYPE_SOA, Message, Record, WireError, decode_message, encode_query,
    normalise,
)

# The shared core, resolved the same way every module in this repository does:
# an installed distribution first, then the sibling folder.
_NETCORE = Path(__file__).resolve().parents[3]
if str(_NETCORE) not in sys.path:
    sys.path.insert(0, str(_NETCORE))

from netcore.measure import Measurement  # noqa: E402
from netcore.rtt import RTTEstimator     # noqa: E402


# The 13 root servers, by IPv4 address (RFC 8109's root hints). Addresses
# rather than names because there is nothing to resolve them with yet — this
# is the bootstrap the whole system hangs from.
ROOT_SERVERS = (
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
)

MAX_DEPTH = 16          # delegation steps before giving up
MAX_CNAME = 8           # CNAME hops before declaring a loop


class ResolveError(Exception):
    """Resolution failed. Names the query and why, never a bare timeout."""


@dataclass
class Answer:
    name: str
    rtype: int
    records: tuple[Record, ...]
    rcode: int = RCODE_NOERROR
    from_cache: bool = False
    queries_sent: int = 0
    elapsed: float = 0.0
    trace: tuple[str, ...] = ()

    @property
    def values(self) -> list[str]:
        return [r.value for r in self.records if r.value]


@dataclass
class Resolver:
    timeout: float = 3.0
    max_retries: int = 2
    cache: Cache = field(default_factory=Cache)
    clock: object = time.monotonic
    #: Per-server RTT estimators, so a slow authoritative server gets a longer
    #: timeout than a fast one instead of every server getting the same guess.
    _rtt: dict[str, RTTEstimator] = field(default_factory=dict)
    latency: Measurement = field(
        default_factory=lambda: Measurement("dns query", unit="ms"))
    queries_sent: int = 0

    # ---- transport -------------------------------------------------------

    def _estimator(self, server: str) -> RTTEstimator:
        est = self._rtt.get(server)
        if est is None:
            est = RTTEstimator(initial_rto=self.timeout)
            self._rtt[server] = est
        return est

    def _exchange(self, server: str, name: str, qtype: int) -> Message | None:
        """One query to one server, with retries. None if it never answered."""
        est = self._estimator(server)

        for attempt in range(self.max_retries + 1):
            # A fresh random identifier per attempt. Reusing it across retries
            # widens the window an off-path attacker has to land a forgery.
            ident = secrets.randbelow(65536)
            query = encode_query(name, qtype, ident, recursion_desired=False)

            budget = min(max(est.rto, 0.05), self.timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(budget)
            started = time.monotonic()
            try:
                sock.sendto(query, (server, 53))
                self.queries_sent += 1
                while True:
                    data, addr = sock.recvfrom(4096)
                    if addr[0] != server:
                        continue          # not from who we asked; keep waiting
                    try:
                        msg = decode_message(data)
                    except WireError:
                        continue          # unparseable: not an answer
                    if msg.ident != ident or not msg.response:
                        continue          # wrong transaction; ignore, do not fail
                    if msg.questions and normalise(msg.questions[0].name) != normalise(name):
                        continue          # answering a different question
                    sample = time.monotonic() - started
                    est.update(sample)
                    self.latency.add(sample * 1000.0)
                    return msg
            except socket.timeout:
                est.on_timeout()
            except OSError:
                return None
            finally:
                sock.close()
        return None

    # ---- resolution ------------------------------------------------------

    def resolve(self, name: str, qtype: int = TYPE_A) -> Answer:
        """Resolve `name`, iteratively from the root, following CNAMEs."""
        started = time.monotonic()
        before = self.queries_sent
        trace: list[str] = []
        target = normalise(name)

        for hop in range(MAX_CNAME):
            answer = self._resolve_once(target, qtype, trace)
            if answer.rcode != RCODE_NOERROR or answer.records:
                cnames = [r for r in answer.records if r.rtype == TYPE_CNAME]
                wanted = [r for r in answer.records if r.rtype == qtype]
                if wanted or not cnames or qtype == TYPE_CNAME:
                    return Answer(target, qtype, answer.records, answer.rcode,
                                  answer.from_cache,
                                  self.queries_sent - before,
                                  time.monotonic() - started, tuple(trace))
                # A CNAME with no answer of the wanted type: restart at the
                # alias. Bounded, because a pair of records can point at each
                # other and a resolver that follows them forever is a loop an
                # unrelated zone owner can install in you.
                target = normalise(str(cnames[0].parsed))
                trace.append(f"CNAME -> {target}")
                continue
            return Answer(target, qtype, answer.records, answer.rcode,
                          answer.from_cache, self.queries_sent - before,
                          time.monotonic() - started, tuple(trace))

        raise ResolveError(f"{name}: more than {MAX_CNAME} CNAME hops")

    def _resolve_once(self, name: str, qtype: int, trace: list[str]) -> Answer:
        now = self.clock()
        cached = self.cache.get(name, qtype, now)
        if cached is not None:
            trace.append(f"cache hit {name}")
            return Answer(name, qtype, cached, RCODE_NOERROR, from_cache=True)

        servers = [(host, ip) for host, ip in ROOT_SERVERS]
        random.shuffle(servers)
        zone = "."

        for depth in range(MAX_DEPTH):
            reply = None
            for host, ip in servers[:3]:
                reply = self._exchange(ip, name, qtype)
                if reply is not None:
                    trace.append(f"{zone or '.'} via {host} ({ip})")
                    break
            if reply is None:
                raise ResolveError(f"{name}: no server for zone {zone!r} answered")

            if reply.rcode == RCODE_NXDOMAIN:
                # Cache the negative answer, bounded by the SOA minimum.
                soa = [r for r in reply.authority if r.rtype == TYPE_SOA]
                ttl = float(soa[0].ttl) if soa else 300.0
                self.cache.put(name, qtype, (), self.clock(),
                               rcode=RCODE_NXDOMAIN, ttl_override=ttl)
                return Answer(name, qtype, (), RCODE_NXDOMAIN)

            if reply.rcode != RCODE_NOERROR:
                return Answer(name, qtype, (), reply.rcode)

            answers = [r for r in reply.answers
                       if r.rtype in (qtype, TYPE_CNAME) and r.rclass == CLASS_IN]
            if answers:
                self.cache.put(name, qtype, tuple(answers), self.clock())
                return Answer(name, qtype, tuple(answers), RCODE_NOERROR)

            # A referral: NS records in the authority section naming the zone
            # one step closer to the answer.
            delegations = [r for r in reply.authority if r.rtype == TYPE_NS]
            if not delegations:
                # NOERROR with nothing: the name exists but has no record of
                # this type. That is an answer, not a failure.
                return Answer(name, qtype, (), RCODE_NOERROR)

            zone = delegations[0].name
            glue = {normalise(r.name): r.value for r in reply.additional
                    if r.rtype == TYPE_A}

            next_servers: list[tuple[str, str]] = []
            for ns in delegations:
                ns_name = normalise(str(ns.parsed or ""))
                ip = glue.get(ns_name)
                if ip:
                    next_servers.append((ns_name, ip))

            if not next_servers:
                # No glue. The nameserver's own address has to be resolved
                # first, which is a separate resolution and the reason a
                # resolver needs to be re-entrant. Bounded by using a fresh
                # resolver with the same cache so the recursion cannot nest
                # arbitrarily deep through this path.
                for ns in delegations[:2]:
                    ns_name = normalise(str(ns.parsed or ""))
                    if not ns_name or ns_name == ".":
                        continue
                    try:
                        sub = Resolver(timeout=self.timeout, cache=self.cache)
                        found = sub.resolve(ns_name, TYPE_A)
                        self.queries_sent += found.queries_sent
                        if found.values:
                            next_servers.append((ns_name, found.values[0]))
                            break
                    except ResolveError:
                        continue

            if not next_servers:
                raise ResolveError(f"{name}: delegation to {zone!r} had no usable address")

            random.shuffle(next_servers)
            servers = next_servers

        raise ResolveError(f"{name}: more than {MAX_DEPTH} delegations")

    # ---- convenience -----------------------------------------------------

    def address(self, name: str) -> str | None:
        answer = self.resolve(name, TYPE_A)
        values = [r.value for r in answer.records if r.rtype == TYPE_A]
        return values[0] if values else None

    def stats(self) -> dict[str, float]:
        out = self.cache.stats()
        out["queries_sent"] = float(self.queries_sent)
        if self.latency:
            out["rtt_p50_ms"] = self.latency.p50
            out["rtt_p99_ms"] = self.latency.p99
        return out
