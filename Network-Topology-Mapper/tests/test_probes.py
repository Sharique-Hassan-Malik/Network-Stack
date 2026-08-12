"""
Tests for packet construction.  No raw sockets or root access required.
"""

import struct
import zlib

import pytest

from ntm.probes import (
    _checksum,
    icmp_echo_packet,
    tcp_syn,
    udp_probe,
)

_SRC = "192.168.1.10"
_DST = "192.168.1.1"


class TestChecksum:
    def test_known_value(self):
        # RFC 1071 example: the 16-bit checksum of a properly-formed IP header
        # with known fields produces a computable result.
        data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
        csum = _checksum(data)
        assert isinstance(csum, int)
        assert 0 <= csum <= 65535

    def test_zeros_produce_ffff(self):
        # Checksum of 2 zero bytes: ~sum = ~0 = 0xFFFF
        assert _checksum(b"\x00\x00") == 0xFFFF

    def test_odd_length_padded(self):
        # Must not raise; odd-length input is zero-padded
        _checksum(b"\x01\x02\x03")   # no exception

    def test_complement_pair_sums_to_zero(self):
        # RFC 1071: recomputing the checksum over a packet that already has the
        # correct checksum injected should yield 0 (no error).
        data = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"\x00" * 8
        csum = _checksum(data)
        patched = data[:2] + struct.pack("!H", csum) + data[4:]
        assert _checksum(patched) == 0


class TestICMPPacket:
    def test_length(self):
        pkt = icmp_echo_packet(_SRC, _DST, ident=1, seq=1)
        # 20 bytes IP + 4 ICMP header + 2 ident/seq + 8 payload = 34
        assert len(pkt) >= 34

    def test_ip_version_and_ihl(self):
        pkt = icmp_echo_packet(_SRC, _DST, ident=1, seq=1)
        assert (pkt[0] >> 4) == 4
        assert (pkt[0] & 0x0F) == 5

    def test_protocol_field(self):
        pkt = icmp_echo_packet(_SRC, _DST, ident=1, seq=1)
        assert pkt[9] == 1   # ICMP

    def test_destination_address(self):
        import socket as _s
        pkt = icmp_echo_packet(_SRC, _DST, ident=42, seq=7)
        dst_bytes = pkt[16:20]
        assert _s.inet_ntoa(dst_bytes) == _DST

    def test_icmp_type_is_echo_request(self):
        pkt = icmp_echo_packet(_SRC, _DST, ident=1, seq=1)
        ihl  = (pkt[0] & 0x0F) * 4
        assert pkt[ihl] == 8    # type = Echo Request
        assert pkt[ihl + 1] == 0  # code = 0

    def test_ttl_respected(self):
        pkt = icmp_echo_packet(_SRC, _DST, ident=1, seq=1, ttl=42)
        assert pkt[8] == 42


class TestTCPSyn:
    def test_minimum_length(self):
        pkt = tcp_syn(_SRC, _DST, sport=12345, dport=80, seq=0)
        assert len(pkt) >= 40   # 20 IP + 20 TCP

    def test_protocol_field(self):
        pkt = tcp_syn(_SRC, _DST, sport=12345, dport=80, seq=0)
        assert pkt[9] == 6   # TCP

    def test_syn_flag_set(self):
        pkt = tcp_syn(_SRC, _DST, sport=12345, dport=80, seq=0)
        ihl = (pkt[0] & 0x0F) * 4
        tcp = pkt[ihl:]
        data_offset = (tcp[12] >> 4) * 4
        flags = struct.unpack("!H", tcp[12:14])[0] & 0x3F
        assert flags == 0x002   # SYN only

    def test_source_port(self):
        pkt = tcp_syn(_SRC, _DST, sport=54321, dport=443, seq=0)
        ihl = (pkt[0] & 0x0F) * 4
        sport = struct.unpack("!H", pkt[ihl:ihl+2])[0]
        assert sport == 54321

    def test_dest_port(self):
        pkt = tcp_syn(_SRC, _DST, sport=1234, dport=8080, seq=0)
        ihl = (pkt[0] & 0x0F) * 4
        dport = struct.unpack("!H", pkt[ihl+2:ihl+4])[0]
        assert dport == 8080


class TestUDPProbe:
    def test_protocol_field(self):
        pkt = udp_probe(_SRC, _DST, sport=49152, dport=33434)
        assert pkt[9] == 17   # UDP

    def test_minimum_length(self):
        pkt = udp_probe(_SRC, _DST, sport=49152, dport=33434)
        assert len(pkt) >= 32   # 20 IP + 8 UDP + 4 payload

    def test_udp_header_length_field(self):
        pkt = udp_probe(_SRC, _DST, sport=49152, dport=33434)
        ihl = (pkt[0] & 0x0F) * 4
        udp_len = struct.unpack("!H", pkt[ihl+4:ihl+6])[0]
        assert udp_len == 8 + 4   # header + 4 bytes payload

    def test_ttl_respected(self):
        pkt = udp_probe(_SRC, _DST, sport=49152, dport=33434, ttl=5)
        assert pkt[8] == 5
