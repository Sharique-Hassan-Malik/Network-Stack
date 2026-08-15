# Architecture

Six modules, one core. Each module's own design is documented in
[`docs/`](docs); this is about what they share and, as importantly, what they
deliberately do not.

```
                            netcore/
        ┌──────────────┬──────────────┬──────────────┐
       rtt.py     congestion.py    measure.py    simulate.py
    RFC 6298      Reno/CUBIC/BBR   percentiles   one bottleneck
        │              │                │
   ┌────┴────┐    ┌────┴────┐           │
  quic   transport  quic  transport   http-benchmark
```

## What was written twice

**RFC 6298.** Both transports implemented it and reached the same constants —
α=1/8, β=1/4, K=4 — with different framing. QUIC's handled the peer's reported
ack delay and applied a clock-granularity floor. The other had explicit Karn
backoff. Neither was wrong; two of them was.

`netcore/rtt.py` is the union. `granularity` and `max_ack_delay` default to
zero, so a plain RFC 6298 consumer gets exactly its previous behaviour, and
`initial_rto` is a parameter because RFC 6298 states one second while RFC 9002
derives roughly the same number a different way — both are right for their
protocol, and a computed compromise would be right for neither.

One subtlety worth keeping: the ack-delay subtraction is floored at `min_rtt`.
A peer that over-reports its delay would otherwise drive SRTT below anything
physically observed.

**Congestion control.** The reliable transport had CUBIC and BBR. QUIC had a
Reno welded into `RecoveryManager` with no way to swap it. All three now sit
behind one three-method interface, and QUIC's constructor takes the name:

```python
RecoveryManager(congestion="bbr")
```

That is the merge paying for itself rather than only deduplicating — QUIC
gained two algorithms it never had.

Two things had to change for it to be real. `build()` filters options by the
controller's signature, because only the time-driven algorithms take a `clock`
and a caller configuring several should not have to know which; an option no
controller accepts is still an error. And BBR's and CUBIC's clocks became
injectable, because their state machines advance with elapsed time and cannot
be stepped by a simulation that does not move the wall clock.

**Percentiles.** Six tools measuring latency six ways. Consolidating them onto
`netcore/measure.py` also fixed a bug: the HTTP benchmark computed percentiles
as `sorted[int(n * pct / 100) - 1]`, which for ten requests returned the ninth
value as the p99 and the fifth as the p50. It under-reported precisely the tail
a benchmark exists to report. The shared function interpolates, which is what
NumPy and most tooling do, and the choice is written down in one place.

`Measurement` keeps the raw samples rather than only a summary, because a p99
cannot be recovered from a mean and merging two summaries is not the same as
summarising the union.

## What is deliberately not shared

The topology mapper's graph is IP-level, discovered by traceroute, with
RTT-weighted edges between addresses. The SDN controller's is switch-and-port
level, keyed by datapath ID, carrying host locations, and it exists to install
flow rules.

They look like the same thing. Merging them would either lose the port detail
the controller needs or bolt datapath IDs onto a traceroute where they mean
nothing. Only one of the two had a shortest-path implementation, so there was
no duplicate to remove either. A shared graph module here would have been an
integration invented to look like one. They stay separate.

## The simulator

`netcore/simulate.py` exists because sharing the controllers is only worth
something if you can tell them apart. It is a fixed-bandwidth, fixed-delay link
with a finite queue and a loss rate, driven in whole round trips.

It reproduces the one distinction that matters: BBR targets the
bandwidth-delay product and so sits at a **lower** RTT than Reno or CUBIC on
the same link, which stand in a full queue for less throughput. That is the
property BBR was designed for, and it is asserted in the tests.

It is a model, not a network — no competing flow, no reordering, no variable
delay — and both the CLI output and the module docstring say so. Numbers from
it describe the algorithm, not your link.

## Standalone and integrated

Each module folder is its own source root, so `modules/quic` holds the `quic`
package and runs from that directory alone. `netcore` is stdlib-only, and each
module reaches it with a three-line path bootstrap, so importing the shared
estimator costs a standalone module no dependencies.

`ctp.rtt` and `ctp.congestion` are now thin re-export modules rather than
implementations. Keeping the names means every existing import and every test
in that module continued to work through the move, which is how the merge was
verified: 38 transport tests and 77 QUIC tests passed before and after, on the
same numbers.

## Test layout

`pytest` from the repository root collects every module. Two things make that
work, and both were found by trying it:

- **`--import-mode=importlib`.** Several modules ship their own `tests`
  package, and the default prepend mode resolves them all to one top-level
  name, so a combined run collides.
- **A root `conftest.py`** that puts every module folder on `sys.path`, since
  each is its own source root.

The container-runtime module's test helpers moved out of its `conftest.py` for
the same reason: `from conftest import ...` resolves to whichever conftest is
nearest, which becomes the repository root's once everything is collected
together.
