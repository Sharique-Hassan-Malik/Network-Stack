"""
Hierarchical Navigable Small World (HNSW) index.

Reference:
    Malkov, Y. A. and Yashunin, D. A. (2018). Efficient and robust approximate
    nearest neighbor search using Hierarchical Navigable Small World graphs.
    IEEE Transactions on Pattern Analysis and Machine Intelligence, 42(4).

Algorithm overview
------------------
The index is a multi-layer proximity graph. Layer 0 contains every node;
higher layers contain exponentially fewer nodes sampled stochastically at
insert time. Each node stores at most M (or M0 = 2*M at layer 0) bi-
directional edges per layer.

insert(v):
    1. Sample the node's top layer l ~ Floor(−ln(U) × mL), cap at max_layer.
    2. Greedily descend from the entry point down to l+1, using ef=1.
    3. From layer l down to 0, run beam search (ef=ef_construction) and
       connect the ef_construction nearest found neighbours, pruning to M
       (or M0 at layer 0) via the heuristic described in the paper.

search(q, k, ef):
    1. Greedily descend from the entry point to layer 1 (ef=1 each layer).
    2. Run beam search at layer 0 with the given ef value.
    3. Return the k nearest candidates.

Beam search (Algorithm 2 from the paper):
    - Maintain a min-heap of candidates and a max-heap of found results.
    - At each step expand the closest unvisited candidate and update both
      heaps, stopping when the closest candidate is farther than the worst
      result found so far.
"""

from __future__ import annotations

import heapq
import math
import pickle
import random
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import numpy as np

from ..distance.metrics import get as get_metric


@dataclass
class _Node:
    """One vector with its adjacency lists across all layers."""
    id:       int
    vector:   np.ndarray
    metadata: Any
    # neighbours[layer] = list of neighbour node ids
    neighbours: list[list[int]] = field(default_factory=list)


class HNSWIndex:
    """
    HNSW approximate nearest-neighbour index.

    Parameters
    ----------
    dim:              Dimensionality of all vectors.
    metric:           One of 'cosine', 'dot' or 'euclidean'.
    M:                Maximum number of edges per node per layer (default 16).
    ef_construction:  Beam width during index construction (default 200).
    ef_search:        Default beam width during query (default 50).
    seed:             RNG seed for reproducible layer assignment.
    """

    def __init__(
        self,
        dim: int,
        metric: str = "cosine",
        M: int = 16,
        ef_construction: int = 200,
        ef_search: int = 50,
        seed: Optional[int] = None,
    ) -> None:
        if dim < 1:
            raise ValueError("dim must be >= 1")
        if M < 2:
            raise ValueError("M must be >= 2")
        if ef_construction < M:
            raise ValueError("ef_construction must be >= M")

        self.dim            = dim
        self.metric         = metric
        self.M              = M
        self.M0             = 2 * M     # layer-0 edges cap
        self.ef_construction = ef_construction
        self.ef_search      = ef_search

        self._dist: Callable[[np.ndarray, np.ndarray], float] = get_metric(metric)
        self._nodes: list[_Node] = []
        self._entry_point: Optional[int] = None
        self._max_layer: int = 0
        self._mL: float = 1.0 / math.log(M)
        self._rng = random.Random(seed)
        self._lock = threading.Lock()

    # Pickle support: threading.Lock is not serialisable; recreate it on load.
    def __getstate__(self) -> dict:
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, vector: np.ndarray, metadata: Any = None) -> int:
        """
        Insert *vector* into the index.

        Returns the assigned integer ID (0-based, monotonically increasing).
        Thread-safe for concurrent inserts.
        """
        vec = self._validate(vector)
        with self._lock:
            node_id = len(self._nodes)
            node_layer = self._random_layer()
            node = _Node(id=node_id, vector=vec, metadata=metadata,
                         neighbours=[[] for _ in range(node_layer + 1)])
            self._nodes.append(node)

            if self._entry_point is None:
                self._entry_point = node_id
                self._max_layer   = node_layer
                return node_id

            ep = self._entry_point

            # Phase 1: descend greedy from max_layer down to node_layer+1
            for lc in range(self._max_layer, node_layer, -1):
                ep = self._greedy_search(vec, ep, lc)

            # Phase 2: beam search and wiring from node_layer down to 0
            for lc in range(min(node_layer, self._max_layer), -1, -1):
                candidates = self._beam_search(vec, ep, self.ef_construction, lc)
                M_cap = self.M0 if lc == 0 else self.M
                neighbours = self._select_neighbours(vec, candidates, M_cap)
                node.neighbours[lc] = [nid for _, nid in neighbours]

                for _, nid in neighbours:
                    nb = self._nodes[nid]
                    if lc >= len(nb.neighbours):
                        continue
                    nb.neighbours[lc].append(node_id)
                    M_nb = self.M0 if lc == 0 else self.M
                    if len(nb.neighbours[lc]) > M_nb:
                        nb.neighbours[lc] = self._prune(nb, lc, M_nb)

                if candidates:
                    ep = candidates[0][1]

            if node_layer > self._max_layer:
                self._entry_point = node_id
                self._max_layer   = node_layer

            return node_id

    def search(
        self,
        query: np.ndarray,
        k: int = 10,
        ef: Optional[int] = None,
    ) -> list[tuple[float, int, Any]]:
        """
        Find the *k* approximate nearest neighbours of *query*.

        Returns a list of (distance, id, metadata) tuples sorted by
        ascending distance.

        Parameters
        ----------
        query: Query vector (must match index dimensionality).
        k:     Number of results to return.
        ef:    Beam width; defaults to max(k, self.ef_search).
        """
        if not self._nodes:
            return []

        q = self._validate(query)
        ef = max(k, ef if ef is not None else self.ef_search)

        with self._lock:
            ep = self._entry_point

            for lc in range(self._max_layer, 0, -1):
                ep = self._greedy_search(q, ep, lc)

            candidates = self._beam_search(q, ep, ef, 0)

        results = []
        for dist, nid in candidates[:k]:
            node = self._nodes[nid]
            results.append((dist, nid, node.metadata))
        return results

    def __len__(self) -> int:
        return len(self._nodes)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialise the index to *path* using pickle."""
        with open(path, "wb") as fh:
            pickle.dump(self, fh, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> "HNSWIndex":
        """Deserialise a previously saved index from *path*."""
        with open(path, "rb") as fh:
            obj = pickle.load(fh)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected HNSWIndex, got {type(obj)}")
        return obj

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self, vec: np.ndarray) -> np.ndarray:
        arr = np.asarray(vec, dtype=np.float32)
        if arr.ndim != 1:
            raise ValueError(f"Expected 1-D vector, got shape {arr.shape}")
        if arr.shape[0] != self.dim:
            raise ValueError(
                f"Vector dimension {arr.shape[0]} does not match index dimension {self.dim}"
            )
        return arr

    def _random_layer(self) -> int:
        """Sample the top layer for a new node using the exponential distribution."""
        return min(
            int(math.floor(-math.log(self._rng.random() + 1e-10) * self._mL)),
            self._max_layer + 1,
        )

    def _dist_to(self, vec: np.ndarray, node_id: int) -> float:
        return self._dist(vec, self._nodes[node_id].vector)

    def _greedy_search(self, vec: np.ndarray, ep: int, layer: int) -> int:
        """Single-step greedy descent: follow the best neighbour until no improvement."""
        best   = ep
        best_d = self._dist_to(vec, ep)
        improved = True
        while improved:
            improved = False
            node = self._nodes[best]
            if layer >= len(node.neighbours):
                break
            for nid in node.neighbours[layer]:
                d = self._dist_to(vec, nid)
                if d < best_d:
                    best_d   = d
                    best     = nid
                    improved = True
        return best

    def _beam_search(
        self,
        vec: np.ndarray,
        ep: int,
        ef: int,
        layer: int,
    ) -> list[tuple[float, int]]:
        """
        Algorithm 2 from the HNSW paper.

        Returns up to *ef* (distance, node_id) pairs sorted by ascending distance.
        """
        ep_dist  = self._dist_to(vec, ep)
        visited  = {ep}
        # candidates: min-heap (dist, id) — explore closest first
        # found:      max-heap (−dist, id) — track best ef results
        candidates: list[tuple[float, int]] = [(ep_dist, ep)]
        found: list[tuple[float, int]]      = [(-ep_dist, ep)]

        while candidates:
            c_dist, c_id = heapq.heappop(candidates)
            worst_found  = -found[0][0]

            if c_dist > worst_found:
                break

            node = self._nodes[c_id]
            if layer >= len(node.neighbours):
                continue

            for nid in node.neighbours[layer]:
                if nid in visited:
                    continue
                visited.add(nid)
                n_dist = self._dist_to(vec, nid)
                if n_dist < worst_found or len(found) < ef:
                    heapq.heappush(candidates, (n_dist, nid))
                    heapq.heappush(found, (-n_dist, nid))
                    if len(found) > ef:
                        heapq.heappop(found)

        result = [(-nd, nid) for nd, nid in found]
        result.sort()
        return result

    def _select_neighbours(
        self,
        vec: np.ndarray,
        candidates: list[tuple[float, int]],
        M: int,
    ) -> list[tuple[float, int]]:
        """
        Simple nearest-M selection (Algorithm 3 / heuristic variant omitted
        for clarity). Returns the M closest candidates.
        """
        return candidates[:M]

    def _prune(self, node: _Node, layer: int, M: int) -> list[int]:
        """
        Rebuild the neighbour list for *node* at *layer*, keeping only the M
        closest neighbours by distance.
        """
        pairs = [
            (self._dist(node.vector, self._nodes[nid].vector), nid)
            for nid in node.neighbours[layer]
        ]
        pairs.sort()
        return [nid for _, nid in pairs[:M]]
