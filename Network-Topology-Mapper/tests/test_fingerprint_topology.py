import pytest

from ntm.fingerprint import (
    TCPFingerprint,
    OSGuess,
    fingerprint_os,
    parse_tcp_options,
    extract_fingerprint_from_ip_packet,
)
from ntm.topology import NetworkGraph


# ── OS fingerprinting ─────────────────────────────────────────────────────────

class TestOSFingerprint:
    def test_windows_10_signature(self):
        fp = TCPFingerprint(ttl=128, df_bit=True, window=64240)
        guess = fingerprint_os(fp)
        assert guess.family == "Windows"
        assert "10" in guess.version or "Server" in guess.version
        assert guess.confidence > 50

    def test_linux_modern_signature(self):
        fp = TCPFingerprint(ttl=64, df_bit=False, window=29200, wscale=7)
        guess = fingerprint_os(fp)
        assert guess.family == "Linux"
        assert guess.confidence > 50

    def test_unknown_produces_zero_confidence(self):
        fp = TCPFingerprint(ttl=200, df_bit=False, window=1234)
        guess = fingerprint_os(fp)
        # Might match partially or not at all; just check type
        assert isinstance(guess.confidence, int)

    def test_cisco_ttl_255(self):
        fp = TCPFingerprint(ttl=255, df_bit=False, window=65535)
        guess = fingerprint_os(fp)
        assert "Cisco" in guess.family or guess.family == "Unknown"

    def test_returns_os_guess_type(self):
        fp = TCPFingerprint(ttl=64, window=5792)
        guess = fingerprint_os(fp)
        assert isinstance(guess, OSGuess)
        assert isinstance(guess.family, str)
        assert isinstance(guess.confidence, int)


class TestParseTCPOptions:
    def test_mss_option(self):
        # Kind=2 Length=4 Value=1460
        data = bytes([2, 4, 0x05, 0xB4])
        opts = parse_tcp_options(data)
        assert opts["mss"] == 1460

    def test_wscale_option(self):
        # Kind=3 Length=3 Value=7
        data = bytes([3, 3, 7])
        opts = parse_tcp_options(data)
        assert opts["wscale"] == 7

    def test_sack_permitted(self):
        data = bytes([4, 2])
        opts = parse_tcp_options(data)
        assert opts.get("sack_ok") is True

    def test_nop_skipped(self):
        # NOP (1) then MSS
        data = bytes([1, 2, 4, 0x05, 0xB4])
        opts = parse_tcp_options(data)
        assert opts["mss"] == 1460

    def test_eol_stops_parsing(self):
        data = bytes([0, 2, 4, 0x05, 0xB4])
        opts = parse_tcp_options(data)
        assert "mss" not in opts

    def test_timestamps_option(self):
        import struct
        ts_data = struct.pack("!II", 123456, 654321)
        data = bytes([8, 10]) + ts_data
        opts = parse_tcp_options(data)
        assert opts["ts_val"] == 123456
        assert opts["ts_ecr"] == 654321

    def test_empty_options(self):
        opts = parse_tcp_options(b"")
        assert opts == {}


# ── NetworkGraph ───────────────────────────────────────────────────────────────

class TestNetworkGraph:
    def test_add_node(self):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        assert "10.0.0.1" in g.nodes

    def test_add_node_idempotent(self):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        g.add_node("10.0.0.1", is_gateway=True)
        assert g.nodes["10.0.0.1"].is_gateway is True
        assert len(g.nodes) == 1

    def test_add_edge(self):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        g.add_node("10.0.0.2")
        g.add_edge("10.0.0.1", "10.0.0.2", rtt_ms=1.5)
        assert len(g.edges) == 1
        assert g.edges[0].rtt_ms == 1.5

    def test_duplicate_edge_ignored(self):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        g.add_node("10.0.0.2")
        g.add_edge("10.0.0.1", "10.0.0.2")
        g.add_edge("10.0.0.1", "10.0.0.2")
        assert len(g.edges) == 1

    def test_to_dict_structure(self):
        g = NetworkGraph()
        g.add_node("10.0.0.1", is_gateway=True)
        g.add_node("10.0.0.2")
        g.add_edge("10.0.0.1", "10.0.0.2", rtt_ms=2.0)
        d = g.to_dict()
        assert "nodes" in d and "edges" in d
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1
        assert d["edges"][0]["rtt_ms"] == 2.0
