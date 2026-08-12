"""
Collection — high-level document store built on top of HNSWIndex.

A Collection associates each vector with a string key and arbitrary metadata,
provides upsert semantics, and supports serialisation to a single directory.

Usage
-----
    from vecdb import Collection

    col = Collection(name="docs", dim=128, metric="cosine")
    col.upsert("doc:001", vector, {"title": "Hello"})
    results = col.query(query_vec, k=5)
    col.save("./my_index")
    col2 = Collection.load("./my_index")
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any, Optional

import numpy as np

from ..index.hnsw import HNSWIndex


class Collection:
    """
    Named collection of keyed vectors with metadata.

    Parameters
    ----------
    name:   Human-readable identifier.
    dim:    Vector dimensionality.
    metric: Distance metric ('cosine', 'dot' or 'euclidean').
    M, ef_construction, ef_search, seed: Forwarded to HNSWIndex.
    """

    def __init__(
        self,
        name: str,
        dim: int,
        metric: str = "cosine",
        M: int = 16,
        ef_construction: int = 200,
        ef_search: int = 50,
        seed: Optional[int] = None,
    ) -> None:
        self.name   = name
        self.dim    = dim
        self.metric = metric
        self._index = HNSWIndex(
            dim=dim,
            metric=metric,
            M=M,
            ef_construction=ef_construction,
            ef_search=ef_search,
            seed=seed,
        )
        # key → internal node id
        self._key_to_id: dict[str, int] = {}
        # internal node id → key (parallel array)
        self._id_to_key: list[str] = []

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def upsert(
        self,
        key: str,
        vector: np.ndarray,
        metadata: Any = None,
    ) -> None:
        """
        Insert a new vector or silently ignore if the key already exists.

        True upsert (overwriting existing vectors in an HNSW graph) is not
        supported without a full rebuild. For immutable collections this is
        rarely needed. Call rebuild() explicitly if in-place updates are
        required.
        """
        if key in self._key_to_id:
            return
        node_id = self._index.add(vector, metadata=metadata)
        self._key_to_id[key] = node_id
        self._id_to_key.append(key)

    def add_batch(
        self,
        keys: list[str],
        vectors: np.ndarray,
        metadatas: Optional[list[Any]] = None,
    ) -> None:
        """
        Insert multiple vectors. *vectors* must have shape (N, dim).
        *metadatas* is an optional list of length N.
        """
        if vectors.ndim != 2 or vectors.shape[1] != self.dim:
            raise ValueError(
                f"Expected shape (N, {self.dim}), got {vectors.shape}"
            )
        if len(keys) != len(vectors):
            raise ValueError("len(keys) != len(vectors)")
        metas = metadatas or [None] * len(keys)
        for key, vec, meta in zip(keys, vectors, metas):
            self.upsert(key, vec, meta)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def query(
        self,
        vector: np.ndarray,
        k: int = 10,
        ef: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Return the *k* approximate nearest neighbours.

        Each result dict contains:
            key      — the string key supplied at insertion
            distance — raw distance value (metric-dependent)
            metadata — metadata supplied at insertion
        """
        raw = self._index.search(vector, k=k, ef=ef)
        results = []
        for dist, nid, meta in raw:
            results.append({
                "key":      self._id_to_key[nid],
                "distance": dist,
                "metadata": meta,
            })
        return results

    def get(self, key: str) -> Optional[dict[str, Any]]:
        """Return the stored vector and metadata for *key*, or None."""
        nid = self._key_to_id.get(key)
        if nid is None:
            return None
        node = self._index._nodes[nid]
        return {"key": key, "vector": node.vector, "metadata": node.metadata}

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, key: str) -> bool:
        return key in self._key_to_id

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        """
        Save the collection to *directory*.

        Creates two files:
          meta.json   — collection parameters and key mappings
          index.pkl   — serialised HNSWIndex (including all vectors)
        """
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        meta = {
            "name":             self.name,
            "dim":              self.dim,
            "metric":           self.metric,
            "key_to_id":        self._key_to_id,
            "id_to_key":        self._id_to_key,
        }
        with open(d / "meta.json", "w") as fh:
            json.dump(meta, fh, indent=2)
        self._index.save(d / "index.pkl")

    @classmethod
    def load(cls, directory: str | Path) -> "Collection":
        """Load a collection previously saved with save()."""
        d = Path(directory)
        with open(d / "meta.json") as fh:
            meta = json.load(fh)
        col = cls.__new__(cls)
        col.name       = meta["name"]
        col.dim        = meta["dim"]
        col.metric     = meta["metric"]
        col._key_to_id = meta["key_to_id"]
        col._id_to_key = meta["id_to_key"]
        col._index     = HNSWIndex.load(d / "index.pkl")
        return col
