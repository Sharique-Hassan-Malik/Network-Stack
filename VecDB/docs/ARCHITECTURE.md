# Architecture — vecdb

## Overview

vecdb is a vector similarity search engine built from scratch. The core data
structure is a Hierarchical Navigable Small World (HNSW) graph. On top of the
graph sits a Collection layer that adds string keys, metadata and persistence.
No external search library (FAISS, Annoy, ScaNN) is used anywhere; every
algorithm is implemented directly.

---

## Layer diagram

```
┌─────────────────────────────────┐
│         User / CLI              │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│          Collection             │  core/collection.py
│  key → id mapping               │
│  upsert / query / save / load   │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│          HNSWIndex              │  index/hnsw.py
│  multi-layer proximity graph    │
│  add / search / save / load     │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│       Distance Metrics          │  distance/metrics.py
│  cosine / dot / euclidean       │
└─────────────────────────────────┘
```

---

## HNSW algorithm

Reference: Malkov and Yashunin (2018), IEEE TPAMI 42(4).

### Graph structure

The index is a set of nodes connected by directed edges across L+1 layers.
Every node exists at layer 0. Each node is assigned a random top layer at
insert time using:

```
l = floor(−ln(U) × mL),   mL = 1 / ln(M)
```

where U ~ Uniform(0,1). This gives an exponential distribution: on average
1/e ≈ 37% of nodes appear at layer 1, 1/e² ≈ 14% at layer 2, and so on.
The cap at `max_layer + 1` prevents a degenerate single unlucky insert from
creating a very high node and hanging subsequent searches.

Each node stores at most M edges per layer (M0 = 2M at layer 0 to improve
recall on the base layer where all queries terminate).

### Insert (add)

```
Phase 1: greedy descent from max_layer → node_layer + 1  (ef = 1)
Phase 2: for each layer from node_layer → 0:
         beam_search(ef = ef_construction)
         connect M nearest candidates found
         prune any neighbour that now exceeds its M cap
if node_layer > max_layer: update entry point
```

### Search

```
Phase 1: greedy descent from max_layer → 1  (ef = 1)
Phase 2: beam_search at layer 0  (ef = max(k, ef_search))
return top-k results
```

### Beam search (Algorithm 2)

Two heaps are maintained simultaneously:

- `candidates` — min-heap of (distance, id): nodes to explore next.
- `found`       — max-heap of (−distance, id): best ef results found so far.

At each step the closest unvisited candidate is expanded. All its unvisited
neighbours are evaluated. A neighbour is added to both heaps if it improves
on the worst result in `found`, or if `found` has not yet reached capacity ef.
When `found` reaches ef the worst element is evicted. The loop terminates
when the closest unexplored candidate is farther than the worst element in
`found` — no further improvement is possible.

This is the critical insight of HNSW: by terminating early, the algorithm
avoids exhaustive search while still finding high-quality results because the
graph's small-world structure keeps relevant nodes within a small number of
hops.

### Complexity

Build: O(N × log N) expected hops to place each new node.
Query: O(log N) hops in upper layers + O(ef × log ef) at layer 0.
Space: O(N × M × L) edges total.

---

## Distance metrics

All metrics return a non-negative scalar where smaller means closer so they
compose directly with the min-heap in beam search.

| Metric    | Formula                              | Notes                          |
|-----------|--------------------------------------|--------------------------------|
| cosine    | 1 − (a·b) / (‖a‖ ‖b‖), clamped ≥ 0 | float32 rounding can produce   |
|           |                                      | tiny negative values; clamp    |
|           |                                      | fixes this                     |
| dot       | −(a · b)                             | negated so smaller = more      |
|           |                                      | similar                        |
| euclidean | ‖a − b‖₂                             | true metric; satisfies         |
|           |                                      | triangle inequality            |

Metrics are registered in a dict and looked up by name. HNSWIndex and
Collection both delegate to `distance.metrics.get(name)` at construction time.

---

## Collection

Collection wraps HNSWIndex with:

- A bidirectional key ↔ integer-id mapping so users work with string keys.
- Metadata storage (arbitrary Python objects) forwarded to the node.
- `upsert` semantics: a duplicate key is silently ignored rather than raising.
- `add_batch` for bulk insertion with shape validation up front.
- `save` / `load` that serialise `meta.json` (key mappings and parameters)
  separately from `index.pkl` (the full HNSW graph with numpy arrays).

The separation of meta.json and index.pkl is intentional: the metadata file
is human-readable and can be inspected without deserialising the graph.

---

## Persistence

`HNSWIndex.save` / `load` use pickle. The threading.Lock field is stripped
from the pickle state (`__getstate__`) and recreated on load (`__setstate__`).
This is the standard Python pattern for making lock-carrying objects serialisable.

`Collection.save` writes two files to a directory:

```
<dir>/
  meta.json   — name, dim, metric, key_to_id, id_to_key
  index.pkl   — pickled HNSWIndex
```

---

## Benchmark

`vecdb.benchmark.runner.run` measures:

- **recall@k** — fraction of true k-NN (from brute-force exact search) that
  appear in the index's k results, averaged over n_queries queries.
- **QPS** — queries per second at the given ef_search setting.
- **build_s** — wall-clock seconds to insert all N vectors.

Brute force uses `numpy.argpartition` for O(N) per-query exact search;
this is fast enough for benchmark sizes up to ~50k vectors.

---

## Files

```
vecdb/
├── __init__.py                 — public API surface
├── distance/
│   └── metrics.py              — cosine, dot, euclidean, registry
├── index/
│   └── hnsw.py                 — HNSWIndex: full HNSW implementation
├── core/
│   └── collection.py           — Collection: keyed vector store
├── benchmark/
│   └── runner.py               — recall@k and QPS benchmark
└── persist/                    — reserved for future WAL / mmap backends

scripts/
└── vecdb_cli.py                — CLI: bench and demo commands

tests/
├── test_metrics.py             — 12 metric tests
├── test_hnsw.py                — 22 HNSW tests (correctness, recall, persist)
├── test_collection.py          — 19 Collection tests
└── test_benchmark.py           — 6 benchmark smoke tests

docs/
└── ARCHITECTURE.md             — this file
```
