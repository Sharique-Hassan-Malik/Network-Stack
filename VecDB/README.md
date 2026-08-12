# VecDB — Vector Database from Scratch

A vector similarity search engine built entirely from first principles.
The core is a hand-implemented Hierarchical Navigable Small World (HNSW)
graph — the same algorithm underlying Pinecone, Weaviate and Chroma.
No FAISS, no Annoy, no ScaNN.

---

## What it does

Given a collection of high-dimensional vectors (embeddings, signal features,
image descriptors), vecdb builds a multi-layer proximity graph that allows
approximate nearest-neighbour queries in O(log N) time instead of the O(N)
required by exhaustive search.

Supported distance metrics: cosine similarity, dot product and Euclidean (L2).

---

## The hard part

The engineering challenge is implementing beam search correctly on a
dynamically growing graph. Two classic traps:

**Layer overflow on insert.** The paper samples each new node's top layer
from an exponential distribution. Without capping at `max_layer + 1`,
a single unlucky draw early in construction creates a node at layer ~25,000
and every subsequent search has to traverse 25,000 empty layers before
reaching any data. The fix is one line; diagnosing it from a hanging insert
takes longer.

**Beam search termination.** The loop must stop when the closest unexplored
candidate is farther than the worst element already in the result set — not
when the candidate heap is empty. Using the wrong stopping condition silently
degrades recall to near zero because the algorithm explores irrelevant corners
of the graph.

**Threading.Lock is not picklable.** The index uses a reentrant lock for
thread-safe inserts. Python's pickle protocol cannot serialise
`threading.Lock` directly. The fix is `__getstate__` / `__setstate__` to
strip and recreate the lock around the pickle boundary.

---

## Architecture

```
Collection  (string keys, metadata, save/load directory)
    └── HNSWIndex  (multi-layer proximity graph, beam search)
            └── distance.metrics  (cosine / dot / euclidean)
```

See `docs/ARCHITECTURE.md` for the full algorithm walkthrough.

---

## Quick start

```bash
pip install numpy
pip install -e .

# Interactive demo — insert 5000 random vectors and query
python scripts/vecdb_cli.py demo --n 5000 --dim 64 --metric cosine

# Benchmark — recall@10 and QPS on 10k vectors
python scripts/vecdb_cli.py bench --n 10000 --dim 128 --metric cosine
```

---

## Usage

```python
import numpy as np
from vecdb import Collection

col = Collection("docs", dim=128, metric="cosine", M=16, ef_construction=200)

# Insert
col.upsert("doc:001", embedding_vector, metadata={"title": "Hello world"})
col.add_batch(keys, matrix_of_embeddings, metadatas)

# Query
results = col.query(query_vector, k=10)
for r in results:
    print(r["key"], r["distance"], r["metadata"])

# Persist
col.save("./my_index")
col2 = Collection.load("./my_index")

# Direct index access
from vecdb import HNSWIndex
idx = HNSWIndex(dim=64, metric="euclidean", M=16, ef_construction=200, seed=0)
idx.add(vec, metadata=42)
results = idx.search(query, k=5)
```

---

## Benchmark

On random unit vectors (NumPy, single thread, Python 3.12):

| N      | dim | metric  | M  | ef  | recall@10 | QPS    |
|--------|-----|---------|----|-----|-----------|--------|
| 10 000 | 128 | cosine  | 16 | 50  | ≥ 0.92    | ~2 000 |
| 10 000 | 128 | cosine  | 16 | 100 | ≥ 0.97    | ~1 100 |
| 10 000 | 128 | euclidean | 16 | 50 | ≥ 0.90  | ~2 200 |

QPS scales inversely with ef; recall scales with ef. M=16 is a good
default for most embedding workloads.

Run your own numbers:
```bash
python scripts/vecdb_cli.py bench --n 10000 --dim 128 --ef-search 100
```

---

## Tests

```bash
pytest tests/ -v
```

54 tests across metrics, HNSW correctness, Collection API and benchmark.

---

## Tech stack

Python 3.10+, NumPy. No other runtime dependencies.

---

## References

Malkov, Y. A. and Yashunin, D. A. (2018). Efficient and robust approximate
nearest neighbor search using Hierarchical Navigable Small World graphs.
*IEEE Transactions on Pattern Analysis and Machine Intelligence*, 42(4),
824–836. https://doi.org/10.1109/TPAMI.2018.2889473
