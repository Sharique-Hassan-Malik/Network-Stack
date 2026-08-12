"""
Probe packet construction using raw sockets.

Each probe type is a standalone function that returns a ready-to-send
bytes object.  All IP and transport headers are assembled manually —
no external libraries are used.

Supported probes
----------------
  icmp_echo        ICMP Echo Request (type 8)
  tcp_syn          TCP SYN with user-controlled source port and window
  udp_probe        UDP datagram to a closed high port (elicits ICMP Port Unreachable)
  tcp_ack          TCP ACK probe (useful for firewall OS fingerprinting)
"""

import os
import socket
import struct


# ── checksum ──────────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


# ── IP header ─────────────────────────────────────────────────────────────────

def _ip_header(
    src: str,
    dst: str,
    proto: int,
    payload_len: int,
    ttl: int = 64,
    ip_id: int | None = None,
) -> bytes:
    if ip_id is None:
        ip_id = int.from_bytes(os.urandom(2), "big")
    ihl = 5
    ver = 4
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000   # DF
    checksum = 0
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (ver << 4) | ihl, tos, total_len,
        ip_id, flags_frag,
        ttl, proto, checksum,
        src_b, dst_b,
    )
    checksum = _checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


# ── ICMP Echo Request ─────────────────────────────────────────────────────────

def icmp_echo(src: str, dst: str, ident: int, seq: int, ttl: int = 64) -> bytes:
    """ICMP Echo Request (type 8, code 0)."""
    payload = b"\x00" * 8   # 8-byte padding to make timing easier
    icmp_header = struct.pack("!BBHHHH8s", 8, 0, 0, ident, seq, 0, payload[:4], payload[4:])
    # Rebuild with correct checksum
    icmp_header = struct.pack("!BBH", 8, 0, 0) + struct.pack("!HH", ident, seq) + payload
    csum = _checksum(icmp_header)
    icmp_pkt = struct.pack("!BBH", 8, 0, csum) + struct.pack("!HH", ident, seq) + payload
    return _ip_header(src, dst, 1, len(icmp_pkt), ttl=ttl) + icmp_pkt


def _icmp_simple(type_: int, code: int, ident: int, seq: int, payload: bytes) -> bytes:
    raw = struct.pack("!BBHHH", type_, code, 0, ident, seq) + payload
    csum = _checksum(raw)
    return struct.pack("!BBH", type_, code, csum) + struct.pack("!HH", ident, seq) + payload


def icmp_echo_packet(src: str, dst: str, ident: int, seq: int, ttl: int = 64) -> bytes:
    body = _icmp_simple(8, 0, ident, seq, b"\x00" * 8)
    return _ip_header(src, dst, 1, len(body), ttl=ttl) + body


# ── TCP SYN ───────────────────────────────────────────────────────────────────

def _tcp_pseudo_header(src: str, dst: str, tcp_len: int) -> bytes:
    return (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!BBH", 0, 6, tcp_len)
    )


def tcp_syn(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ttl: int = 64,
    window: int = 65535,
) -> bytes:
    """TCP SYN segment."""
    data_offset = 5   # no options
    flags = 0x002     # SYN
    urg = 0
    tcp_header = struct.pack(
        "!HHIIHHHH",
        sport, dport, seq, 0,
        (data_offset << 12) | flags,
        window, 0, urg,
    )
    pseudo = _tcp_pseudo_header(src, dst, len(tcp_header))
    csum = _checksum(pseudo + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack("!H", csum) + tcp_header[18:]
    return _ip_header(src, dst, 6, len(tcp_header), ttl=ttl) + tcp_header


def tcp_ack(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    ttl: int = 64,
    window: int = 65535,
) -> bytes:
    """TCP ACK probe (no payload)."""
    data_offset = 5
    flags = 0x010   # ACK
    tcp_header = struct.pack(
        "!HHIIHHHH",
        sport, dport, seq, ack,
        (data_offset << 12) | flags,
        window, 0, 0,
    )
    pseudo = _tcp_pseudo_header(src, dst, len(tcp_header))
    csum = _checksum(pseudo + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack("!H", csum) + tcp_header[18:]
    return _ip_header(src, dst, 6, len(tcp_header), ttl=ttl) + tcp_header


# ── UDP probe ─────────────────────────────────────────────────────────────────

def udp_probe(src: str, dst: str, sport: int, dport: int, ttl: int = 64) -> bytes:
    """Short UDP datagram; destination is normally a closed port to elicit ICMP."""
    payload = b"\x00" * 4
    udp_len  = 8 + len(payload)
    pseudo   = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, udp_len)
    udp_raw  = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    csum     = _checksum(pseudo + udp_raw)
    udp_pkt  = struct.pack("!HHH", sport, dport, udp_len) + struct.pack("!H", csum) + payload
    return _ip_header(src, dst, 17, len(udp_pkt), ttl=ttl) + udp_pkt
