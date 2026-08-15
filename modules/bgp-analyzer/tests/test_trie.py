from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

import pytest

from bgp_analyzer.core.trie import PrefixTrie


def v4(s: str) -> IPv4Network:
    return IPv4Network(s)


def v6(s: str) -> IPv6Network:
    return IPv6Network(s)


class TestPrefixTrie:

    def test_insert_and_contains_exact(self):
        t = PrefixTrie()
        t.insert(v4("10.0.0.0/8"))
        assert v4("10.0.0.0/8") in t
        assert v4("10.0.0.0/16") not in t

    def test_covering_prefixes_finds_parent(self):
        t = PrefixTrie()
        t.insert(v4("10.0.0.0/8"))
        t.insert(v4("10.1.0.0/16"))
        covering = t.covering_prefixes(v4("10.1.2.0/24"))
        assert v4("10.0.0.0/8") in covering
        assert v4("10.1.0.0/16") in covering

    def test_covering_prefixes_returns_empty_when_none(self):
        t = PrefixTrie()
        t.insert(v4("10.0.0.0/8"))
        assert t.covering_prefixes(v4("11.0.0.0/8")) == []

    def test_more_specific_prefixes(self):
        t = PrefixTrie()
        t.insert(v4("10.0.0.0/8"))
        t.insert(v4("10.1.0.0/16"))
        t.insert(v4("10.1.2.0/24"))
        more_specific = t.more_specific_prefixes(v4("10.1.0.0/16"))
        prefixes = set(str(p) for p in more_specific)
        assert "10.1.0.0/16" in prefixes
        assert "10.1.2.0/24" in prefixes
        assert "10.0.0.0/8" not in prefixes

    def test_all_prefixes(self):
        t = PrefixTrie()
        nets = [v4("1.0.0.0/8"), v4("2.0.0.0/8"), v4("3.0.0.0/8")]
        for n in nets:
            t.insert(n)
        found = set(str(p) for p in t.all_prefixes())
        assert found == {"1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"}

    def test_ipv6_insert_and_contains(self):
        t = PrefixTrie()
        t.insert(v6("2001:db8::/32"))
        assert v6("2001:db8::/32") in t
        assert v6("2001:db8:1::/48") not in t

    def test_ipv6_covering_prefix(self):
        t = PrefixTrie()
        t.insert(v6("2001:db8::/32"))
        covering = t.covering_prefixes(v6("2001:db8:cafe::/48"))
        assert v6("2001:db8::/32") in covering

    def test_not_in_empty_trie(self):
        t = PrefixTrie()
        assert v4("0.0.0.0/0") not in t
