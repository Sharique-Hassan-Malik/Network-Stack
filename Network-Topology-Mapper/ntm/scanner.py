"""
Port scanning module.

Methods
-------
  syn   — raw TCP SYN probe (stealth; requires root). Fastest.
  connect — full TCP connect(). No root required.
  udp   — send UDP; wait for ICMP Port Unreachable or no response.

Results are returned as a dict mapping port → PortState.

PortState
---------
  OPEN      SYN-ACK received (syn) or connect() succeeded (connect)
  CLOSED    RST received (syn) or connection refused (connect)
  FILTERED  No response within timeout
  OPEN_FILTERED  UDP: no response (port may be open or filtered by firewall)
"""

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .probes import tcp_syn, udp_probe

_MAX_WORKERS = 128
_TIMEOUT     = 0.75   # seconds per port


class PortState(Enum):
    OPEN          = auto()
    CLOSED        = auto()
    FILTERED      = auto()
    OPEN_FILTERED = auto()


@dataclass
class PortResult:
    port:    int
    state:   PortState
    proto:   str = "tcp"


def scan_ports(
    target: str,
    ports: list[int],
    method: str = "connect",
    timeout: float = _TIMEOUT,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[PortResult]:
    """
    Scan a list of ports on target using the given method.

    Parameters
    ----------
    target : str
        IPv4 address.
    ports : list[int]
        Port numbers to scan.
    method : "connect" | "syn" | "udp"
    timeout : float
        Per-port timeout in seconds.
    progress_cb : callable, optional
        Called with (done, total).
    """
    fn = {
        "connect": _connect_scan,
        "syn":     _syn_scan,
        "udp":     _udp_scan,
    }.get(method)
    if fn is None:
        raise ValueError(f"Unknown scan method: {method!r}")

    results = []
    total   = len(ports)
    done    = 0
    lock    = threading.Lock()

    def _worker(port: int) -> PortResult:
        return fn(target, port, timeout)

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, total or 1)) as pool:
        futures = {pool.submit(_worker, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            with lock:
                results.append(r)
                done += 1
                if progress_cb:
                    progress_cb(done, total)

    return sorted(results, key=lambda r: r.port)


# ── connect scan ──────────────────────────────────────────────────────────────

def _connect_scan(target: str, port: int, timeout: float) -> PortResult:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        s.close()
        return PortResult(port=port, state=PortState.OPEN)
    except ConnectionRefusedError:
        return PortResult(port=port, state=PortState.CLOSED)
    except (socket.timeout, OSError):
        return PortResult(port=port, state=PortState.FILTERED)
    finally:
        try:
            s.close()
        except OSError:
            pass


# ── SYN scan ──────────────────────────────────────────────────────────────────

def _syn_scan(target: str, port: int, timeout: float) -> PortResult:
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        # Fall back to connect scan when running without privileges
        return _connect_scan(target, port, timeout)

    src = _local_source_ip(target)
    sport = random.randint(49152, 65535)
    seq   = random.randint(0, 2**32 - 1)

    pkt = tcp_syn(src, target, sport, port, seq)
    try:
        send_sock.sendto(pkt, (target, 0))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw, addr = recv_sock.recvfrom(65536)
            except socket.timeout:
                break
            if addr[0] != target:
                continue
            result = _parse_syn_reply(raw, port, sport)
            if result is not None:
                return PortResult(port=port, state=result)
        return PortResult(port=port, state=PortState.FILTERED)
    finally:
        send_sock.close()
        recv_sock.close()


def _parse_syn_reply(raw: bytes, dport: int, our_sport: int) -> PortState | None:
    ihl = (raw[0] & 0x0F) * 4
    if len(raw) < ihl + 20:
        return None
    tcp = raw[ihl:]
    src_port = struct.unpack("!H", tcp[0:2])[0]
    dst_port = struct.unpack("!H", tcp[2:4])[0]
    if src_port != dport or dst_port != our_sport:
        return None
    flags = struct.unpack("!H", tcp[12:14])[0] & 0x3F
    if flags & 0x12 == 0x12:   # SYN+ACK
        return PortState.OPEN
    if flags & 0x04:            # RST
        return PortState.CLOSED
    return None


# ── UDP scan ──────────────────────────────────────────────────────────────────

def _udp_scan(target: str, port: int, timeout: float) -> PortResult:
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        return PortResult(port=port, state=PortState.OPEN_FILTERED, proto="udp")

    src   = _local_source_ip(target)
    sport = random.randint(49152, 65535)
    pkt   = udp_probe(src, target, sport, port)
    try:
        send_sock.sendto(pkt, (target, 0))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw, addr = recv_sock.recvfrom(65536)
            except socket.timeout:
                break
            if addr[0] != target:
                continue
            ihl = (raw[0] & 0x0F) * 4
            if len(raw) < ihl + 8:
                continue
            icmp_type = raw[ihl]
            icmp_code = raw[ihl + 1]
            if icmp_type == 3 and icmp_code == 3:   # Port Unreachable
                return PortResult(port=port, state=PortState.CLOSED, proto="udp")
        return PortResult(port=port, state=PortState.OPEN_FILTERED, proto="udp")
    finally:
        send_sock.close()
        recv_sock.close()


# ── helper ────────────────────────────────────────────────────────────────────

def _local_source_ip(dst: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


# ── common port lists ─────────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2181, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9200, 27017,
    # Additional common services
    20, 69, 79, 88, 102, 119, 161, 179, 194, 389, 427, 465, 500, 514, 515,
    543, 544, 548, 554, 631, 636, 646, 873, 902, 989, 990, 992, 1194, 1701,
    1812, 1813, 2082, 2083, 2086, 2087, 2095, 2096, 2483, 2484, 4333, 5060,
    5061, 5631, 5632, 5800, 5801, 6000, 6001, 8008, 8081,
]
