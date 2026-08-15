"""
Binary trie for IPv4 and IPv6 prefix storage.

Supports:
  insert(prefix)
  __contains__(prefix)         — exact match
  covering_prefixes(prefix)    — all stored prefixes that contain this one
  more_specific_prefixes(p)    — all stored prefixes more specific than p
  all_prefixes()               — iterate all stored prefixes
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network
from typing import Iterator, Optional, Union

IPNetwork = Union[IPv4Network, IPv6Network]


class _Node:
    __slots__ = ("prefix", "children")

    def __init__(self) -> None:
        self.prefix: Optional[IPNetwork] = None
        self.children: list[Optional[_Node]] = [None, None]


class PrefixTrie:
    """Separate tries for IPv4 and IPv6 to keep bit-walking simple."""

    def __init__(self) -> None:
        self._root4 = _Node()
        self._root6 = _Node()

    def _root(self, prefix: IPNetwork) -> _Node:
        return self._root4 if isinstance(prefix, IPv4Network) else self._root6

    @staticmethod
    def _bits(prefix: IPNetwork) -> tuple[int, ...]:
        addr_int = int(prefix.network_address)
        plen = prefix.prefixlen
        total = 32 if isinstance(prefix, IPv4Network) else 128
        return tuple((addr_int >> (total - 1 - i)) & 1 for i in range(plen))

    def insert(self, prefix: IPNetwork) -> None:
        node = self._root(prefix)
        for bit in self._bits(prefix):
            if node.children[bit] is None:
                node.children[bit] = _Node()
            node = node.children[bit]
        node.prefix = prefix

    def __contains__(self, prefix: object) -> bool:
        if not isinstance(prefix, (IPv4Network, IPv6Network)):
            return False
        node = self._root(prefix)
        for bit in self._bits(prefix):
            if node.children[bit] is None:
                return False
            node = node.children[bit]
        return node.prefix is not None

    def covering_prefixes(self, prefix: IPNetwork) -> list[IPNetwork]:
        """Return all stored prefixes that contain the given prefix (less specific or equal)."""
        result: list[IPNetwork] = []
        node = self._root(prefix)
        if node.prefix is not None:
            result.append(node.prefix)
        for bit in self._bits(prefix):
            if node.children[bit] is None:
                break
            node = node.children[bit]
            if node.prefix is not None:
                result.append(node.prefix)
        return result

    def more_specific_prefixes(self, prefix: IPNetwork) -> list[IPNetwork]:
        """Return all stored prefixes that are sub-prefixes of the given prefix."""
        node = self._root(prefix)
        for bit in self._bits(prefix):
            if node.children[bit] is None:
                return []
            node = node.children[bit]
        result: list[IPNetwork] = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n.prefix is not None:
                result.append(n.prefix)
            for child in n.children:
                if child is not None:
                    stack.append(child)
        return result

    def all_prefixes(self) -> Iterator[IPNetwork]:
        for root in (self._root4, self._root6):
            stack: list[_Node] = [root]
            while stack:
                node = stack.pop()
                if node.prefix is not None:
                    yield node.prefix
                for child in node.children:
                    if child is not None:
                        stack.append(child)
