from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

import pytest

from bgp_analyzer.core.types import (
    AS_SEQUENCE,
    AS_SET,
    ASPath,
    ASPathSegment,
    Route,
)


def _seq(*asns: int) -> ASPath:
    return ASPath(segments=(ASPathSegment(kind=AS_SEQUENCE, asns=asns),))


def _set(*asns: int) -> ASPathSegment:
    return ASPathSegment(kind=AS_SET, asns=asns)


class TestASPath:

    def test_origin_returns_last_asn_in_sequence(self):
        path = _seq(1, 2, 3)
        assert path.origin == 3

    def test_origin_none_for_empty_path(self):
        path = ASPath(segments=())
        assert path.origin is None

    def test_all_asns_flattens_segments(self):
        seg1 = ASPathSegment(kind=AS_SEQUENCE, asns=(1, 2))
        seg2 = ASPathSegment(kind=AS_SET, asns=(3, 4))
        seg3 = ASPathSegment(kind=AS_SEQUENCE, asns=(5,))
        path = ASPath(segments=(seg1, seg2, seg3))
        assert path.all_asns == [1, 2, 3, 4, 5]

    def test_length(self):
        assert _seq(10, 20, 30).length == 3

    def test_has_loop_false_for_clean_path(self):
        assert not _seq(1, 2, 3, 4).has_loop()

    def test_has_loop_true_for_repeated_asn(self):
        assert _seq(1, 2, 3, 2, 4).has_loop()

    def test_str_sequence(self):
        assert str(_seq(1, 2, 3)) == "1 2 3"

    def test_str_with_set(self):
        seg_seq = ASPathSegment(kind=AS_SEQUENCE, asns=(1,))
        seg_set = ASPathSegment(kind=AS_SET, asns=(2, 3))
        path = ASPath(segments=(seg_seq, seg_set))
        assert str(path) == "1 {2 3}"


class TestRoute:

    def test_path_str(self):
        r = Route(
            prefix=IPv4Network("192.0.2.0/24"),
            origin_as=64499,
            as_path=_seq(64497, 64499),
            peer_as=64496,
            peer_ip="192.0.2.1",
            timestamp=1000,
        )
        assert r.path_str == "64497 64499"

    def test_origin_str_unknown(self):
        r = Route(
            prefix=IPv4Network("192.0.2.0/24"),
            origin_as=None,
            as_path=None,
            peer_as=None,
            peer_ip=None,
            timestamp=1000,
        )
        assert r.origin_str == "unknown"

    def test_to_dict_keys(self):
        from bgp_analyzer.core.types import Alert
        r = Route(IPv4Network("192.0.2.0/24"), 64499, _seq(1, 2), 1, "1.1.1.1", 1000)
        alert = Alert("origin_hijack", "high", r.prefix, "desc", current_route=r)
        d = alert.to_dict()
        assert "kind" in d and "severity" in d and "prefix" in d
        assert d["current"]["origin_as"] == 64499
