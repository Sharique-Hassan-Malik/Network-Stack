from __future__ import annotations

import io
import textwrap
from ipaddress import IPv4Network

import pytest

from bgp_analyzer.parsers.bgpdump import _parse_path_str, parse_bgpdump


class TestParsePathStr:

    def test_simple_sequence(self):
        path = _parse_path_str("1 2 3")
        assert path is not None
        assert path.all_asns == [1, 2, 3]
        assert path.origin == 3

    def test_empty_string(self):
        assert _parse_path_str("") is None
        assert _parse_path_str("   ") is None

    def test_path_with_as_set(self):
        path = _parse_path_str("1 {2 3} 4")
        assert path is not None
        asns = path.all_asns
        assert 1 in asns
        assert 2 in asns
        assert 3 in asns
        assert 4 in asns

    def test_single_asn(self):
        path = _parse_path_str("65001")
        assert path is not None
        assert path.origin == 65001

    def test_handles_invalid_tokens(self):
        path = _parse_path_str("1 foo 2")
        assert path is not None
        assert path.all_asns == [1, 2]


BGPDUMP_SAMPLE = textwrap.dedent("""\
    TABLE_DUMP2|1700000000|B|1.2.3.4|64496|192.0.2.0/24|64497 64499|IGP|5.6.7.8|
    TABLE_DUMP2|1700000000|B|1.2.3.5|64498|198.51.100.0/24|64498 64500|IGP|5.6.7.9|
    BGP4MP|1700000001|A|10.0.0.1|64496|203.0.113.0/24|64496 64501|IGP|5.6.7.10
    BGP4MP|1700000001|W|10.0.0.1|64496|192.0.2.1/32
    # comment line
    garbage line
""")


class TestParseBgpdump:

    def test_parses_expected_routes(self, tmp_path):
        f = tmp_path / "dump.txt"
        f.write_text(BGPDUMP_SAMPLE)
        routes = list(parse_bgpdump(str(f)))
        prefixes = [str(r.prefix) for r in routes]
        assert "192.0.2.0/24" in prefixes
        assert "198.51.100.0/24" in prefixes
        assert "203.0.113.0/24" in prefixes

    def test_withdrawal_skipped(self, tmp_path):
        f = tmp_path / "dump.txt"
        f.write_text(BGPDUMP_SAMPLE)
        routes = list(parse_bgpdump(str(f)))
        prefixes = [str(r.prefix) for r in routes]
        assert "192.0.2.1/32" not in prefixes

    def test_peer_as_parsed(self, tmp_path):
        f = tmp_path / "dump.txt"
        f.write_text(BGPDUMP_SAMPLE)
        routes = list(parse_bgpdump(str(f)))
        r = next(r for r in routes if str(r.prefix) == "192.0.2.0/24")
        assert r.peer_as == 64496

    def test_origin_as_set(self, tmp_path):
        f = tmp_path / "dump.txt"
        f.write_text(BGPDUMP_SAMPLE)
        routes = list(parse_bgpdump(str(f)))
        r = next(r for r in routes if str(r.prefix) == "192.0.2.0/24")
        assert r.origin_as == 64499

    def test_gzip_transparent(self, tmp_path):
        import gzip
        gz = tmp_path / "dump.txt.gz"
        with gzip.open(gz, "wt") as fh:
            fh.write(BGPDUMP_SAMPLE)
        routes = list(parse_bgpdump(str(gz)))
        assert len(routes) == 3
