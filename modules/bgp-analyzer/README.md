# BGP Hijack Analyzer

> Part of the [Network Stack](../../README.md). Runs standalone from this
> folder; its RTT estimation and congestion control come from `netcore`.

Parse BGP routing table dumps from RIPE NCC or RouteViews, build a
historical baseline and detect anomalous route announcements — prefix
hijacks, sub-prefix hijacks, route leaks and bogon propagation.

No network connections are made at runtime. All analysis is offline
static inspection of already-downloaded MRT files.

---

## Features

- MRT binary parser (RFC 6396) — TABLE_DUMP_V2 and BGP4MP record types,
  both 2-byte and 4-byte ASN encodings, AS4_PATH attribute merging
- bgpdump `-m` text format parser as an alternative input
- Auto-detection of file format by header sniffing
- Transparent decompression of `.gz` and `.bz2` files
- Binary patricia trie for O(prefix_len) covering-prefix and sub-prefix queries
- Five independent detectors:
  - **Origin hijack** — prefix announced by AS not in baseline origin set
  - **Sub-prefix hijack** — more-specific prefix announced by foreign AS
  - **Route leak** — abnormal path length increase or unexpected Tier-1 transit
  - **Bogon prefix** — announcement of IANA special-purpose address space
  - **Bogon AS / path anomaly** — private ASNs in global table, AS path loops
- Per-detector enable/disable and minimum severity filter
- Rich colour terminal output and JSON report
- `--demo` mode requires no data files — runs synthetic attack scenarios
- `--baseline-stats` shows baseline statistics for any dump file

---

## Requirements

Python 3.11 or later. One runtime dependency:

```
pip install rich
```

---

## Installation

```
git clone https://github.com/Sharique-Hassan-Malik/BGP-Hijack-Analyzer
cd bgp-hijack-analyzer
pip install -e .
```

---

## Quick Start

### Demo mode (no data files needed)

```
bgp-analyzer --demo
```

Runs six synthetic attack scenarios against a generated baseline and
prints a colour-coded alert table.

### Real data

Download a RIB snapshot and a recent update stream from RIPE NCC RIS:

```
wget https://data.ris.ripe.net/rrc00/latest-bview.gz
wget https://data.ris.ripe.net/rrc00/latest-update.gz

bgp-analyzer latest-bview.gz latest-update.gz
```

The full-table snapshot is the baseline. The update stream is scanned
for anomalies against that baseline.

### Save a JSON report

```
bgp-analyzer baseline.gz current.gz --json report.json
```

### Filter by severity

```
bgp-analyzer baseline.gz current.gz --min-severity high
```

### Disable specific detectors

```
bgp-analyzer baseline.gz current.gz --disable route_leak --disable path_anomaly
```

### Baseline statistics

```
bgp-analyzer --baseline-stats latest-bview.gz
```

Prints prefix count, route count and the ten most-announced prefixes.

---

## Detector Reference

| Detector | Kind | Description |
|---|---|---|
| Origin hijack | `origin_hijack` | Prefix announced by an AS not seen in the baseline for that prefix |
| Sub-prefix hijack | `subprefix_hijack` | More-specific prefix announced by an AS that does not own any covering prefix |
| Route leak | `route_leak` | AS path length significantly exceeds baseline average or Tier-1 transits a route it should not see |
| Bogon prefix | `bogon_prefix` | Announcement overlaps IANA special-purpose ranges (RFC 1918, RFC 5737, etc.) |
| Bogon AS | `bogon_as` | AS path contains private-use or reserved ASNs (RFC 6996, RFC 6793) |
| Path loop | `path_loop` | Same ASN appears more than once in the AS path |
| Path anomaly | `path_anomaly` | Private ASN propagating in the global routing table |

Severity levels: `high`, `medium`, `low`.

---

## Data Sources

| Source | URL | Format |
|---|---|---|
| RIPE NCC RIS | https://ris.ripe.net/dumps/ | MRT binary (bview snapshots and update streams) |
| RouteViews | http://archive.routeviews.org/ | MRT binary and bgpdump text |

Both sources publish files compressed with gzip or bzip2. The parser
handles both transparently.

---

## Running Tests

```
pip install pytest
pytest tests/ -v
```

58 tests covering the trie, all five detectors, the bgpdump parser,
the MRT parser and the full analyzer pipeline.

---

## File Map

| Path | Description |
|---|---|
| `bgp_analyzer/core/types.py` | `Route`, `ASPath`, `ASPathSegment`, `Alert` dataclasses |
| `bgp_analyzer/core/trie.py` | Binary patricia trie for prefix containment queries |
| `bgp_analyzer/core/baseline.py` | Per-prefix profile store built from historical routes |
| `bgp_analyzer/core/asinfo.py` | Bogon ranges, private ASN ranges, Tier-1 ASN set |
| `bgp_analyzer/parsers/mrt.py` | RFC 6396 MRT binary format parser |
| `bgp_analyzer/parsers/bgpdump.py` | bgpdump `-m` text format parser |
| `bgp_analyzer/parsers/__init__.py` | Auto-detecting `load_routes()` |
| `bgp_analyzer/detectors/` | One module per detector |
| `bgp_analyzer/analyzer.py` | `BGPHijackAnalyzer` orchestrator and `DetectorConfig` |
| `bgp_analyzer/generator.py` | Synthetic route generator for demo mode and tests |
| `bgp_analyzer/report/renderer.py` | Rich terminal renderer |
| `bgp_analyzer/report/json_report.py` | JSON serializer |
| `bgp_analyzer/cli.py` | argparse CLI entry point |
| `tests/` | pytest suite — 58 tests |
| `docs/architecture.md` | Component map, data-flow detail, detector logic |
