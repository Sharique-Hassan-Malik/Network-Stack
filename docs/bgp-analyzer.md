# Architecture

## Overview

The analyzer is a pure static analysis tool. It never establishes network
connections. All data comes from files already downloaded from a route
collector such as RIPE NCC RIS or RouteViews.

The pipeline is:

```
Input files
    │
    ▼
Parsers (MRT binary or bgpdump text)
    │  stream Route objects one at a time
    ▼
Baseline builder
    │  additive fold over historical routes
    │  builds per-prefix PrefixProfile
    │  inserts prefixes into PrefixTrie
    ▼
BGPHijackAnalyzer.analyze()
    │  streams current routes
    │  runs each Route through all enabled detectors
    │  deduplicates alerts by (kind, prefix, origin_as)
    ▼
AnalysisResult
    │
    ├── terminal renderer (Rich)
    └── JSON report
```

---

## Component Map

| Module | Responsibility |
|---|---|
| `core/types.py` | `Route`, `ASPath`, `ASPathSegment`, `Alert` — all immutable frozen dataclasses |
| `core/trie.py` | Binary patricia trie — O(prefix_len) insert and lookup, used for covering-prefix and sub-prefix queries |
| `core/baseline.py` | `Baseline` — dict of `PrefixProfile` keyed by prefix string, backed by a `PrefixTrie` |
| `core/asinfo.py` | Bogon prefix ranges, private and reserved ASN ranges, Tier-1 ASN set |
| `parsers/mrt.py` | RFC 6396 MRT binary parser — TABLE_DUMP_V2 and BGP4MP record types, all BGP UPDATE attributes |
| `parsers/bgpdump.py` | bgpdump `-m` text format parser — pipe-delimited one-route-per-line |
| `parsers/__init__.py` | `load_routes()` — auto-detects binary vs text by sniffing the first MRT header |
| `detectors/base.py` | `BaseDetector` ABC — single `check(route, baseline) → Iterator[Alert]` method |
| `detectors/origin_hijack.py` | Origin AS not in baseline for exact-match prefix |
| `detectors/subprefix.py` | More-specific prefix announced by AS that does not own any covering prefix |
| `detectors/route_leak.py` | Path length excess above baseline average or unexpected Tier-1 transit |
| `detectors/bogon.py` | Prefix overlaps IANA special-purpose ranges or path contains bogon ASN |
| `detectors/path_anomaly.py` | AS path loop (repeated ASN) or private ASN propagating in global table |
| `analyzer.py` | `BGPHijackAnalyzer` — orchestrates baseline and detector pipeline, `DetectorConfig` |
| `generator.py` | Synthetic route generator for `--demo` mode and testing |
| `report/renderer.py` | Rich terminal output — summary panel, breakdown table, alert table |
| `report/json_report.py` | JSON serializer for `AnalysisResult` |
| `cli.py` | argparse CLI with `--demo`, `--baseline-stats`, `--json`, `--min-severity`, `--disable` |

---

## Data Flow Detail

### Route object

```
Route
  prefix       : IPv4Network | IPv6Network
  origin_as    : int | None            ← last ASN in the final AS_SEQUENCE segment
  as_path      : ASPath | None
  peer_as      : int | None
  peer_ip      : str | None
  timestamp    : int                   ← Unix epoch from MRT header
  next_hop     : str | None
  local_pref   : int | None
  med          : int | None
  communities  : tuple[str, ...]       ← "ASN:VALUE" strings
```

### Baseline build

Routes stream from `load_routes()`. Each route is folded into `Baseline.add_route()`:
- First occurrence of a prefix creates a `PrefixProfile` and inserts the prefix into
  the `PrefixTrie`.
- Subsequent occurrences update the profile — origin ASes and peer ASes accumulate
  in sets; path strings and sample routes are capped at fixed limits to bound memory.

### Detector dispatch

Each detector's `check()` method receives one Route and the fully-built Baseline.
Detectors are stateless and produce zero or more `Alert` objects. The analyzer
deduplicates by `(kind, prefix, origin_as)` so that a prefix appearing in multiple
peers only produces one alert per attack pattern.

---

## Prefix Trie

The trie is a standard binary patricia trie with separate roots for IPv4 and IPv6.
Bit-walking for IPv4 goes 32 levels deep at most; IPv6 goes 128 levels.

- `covering_prefixes(p)` walks the path of bits in `p` from the root, collecting
  every node that has a stored prefix along the way. This returns all less-specific
  prefixes that contain `p`.
- `more_specific_prefixes(p)` walks to the node for `p` then does a full DFS
  from that node, collecting every prefix below it.

Both operations are O(max_prefix_len + result_size).

---

## Detector Logic

### Origin Hijack

For a prefix with an exact baseline entry, if the announcing AS is not in
`profile.origin_ases`, an alert fires. Severity is `high` for prefixes with one or
two known origins, `medium` for well-travelled prefixes with many observed origins.

### Sub-prefix Hijack

For a prefix not in the baseline, the covering prefix with the longest mask
is found via the trie. If the announcing AS does not appear in the origin set of
any covering prefix, the route is flagged. Severity is `high` for host routes (`/32`
or `/128`) and for covering prefixes with a single stable origin.

### Route Leak

Two checks are applied only to prefixes with baseline data. The path-length check
fires when the current hop count exceeds the baseline average by `PATH_LEN_EXCESS`
(default 3). The Tier-1 transit check flags any Tier-1 ASN appearing between two
non-Tier-1 neighbors in a path where that Tier-1 was never observed for this prefix.

### Bogon

Prefix is checked against IANA special-purpose IPv4 and IPv6 ranges. Path is checked
for private-use ASNs (RFC 6996), AS_TRANS (RFC 6793) and reserved values 0, 65535
and 4294967295. Documentation-range ASNs (64496–64511, 65536–65551 per RFC 5398) are
intentionally not flagged as bogons — they are used in test data and documentation and
should not produce noise in a real analysis pipeline.

### Path Anomaly

The `has_loop()` check on `ASPath` runs a single-pass seen-set over `all_asns`.
The private-AS-leak check filters `all_asns` for RFC 6996 private-use ranges.

---

## Real Data Sources

RIPE NCC RIS (https://ris.ripe.net/dumps/) and RouteViews
(http://archive.routeviews.org/) publish MRT binary dumps and bgpdump
text exports in real time and as daily archives.

Typical workflow:

```
# Download a RIS full-table dump (bview = RIB snapshot, updates = BGP4MP stream)
wget https://data.ris.ripe.net/rrc00/latest-bview.gz   # baseline
wget https://data.ris.ripe.net/rrc00/latest-update.gz  # current

bgp-analyzer latest-bview.gz latest-update.gz --json report.json
```

Both `.gz` (gzip) and `.bz2` (bzip2) compressed files are handled transparently.
