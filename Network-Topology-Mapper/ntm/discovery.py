"""
Host discovery over a CIDR subnet.

Strategy
--------
1. Send ICMP Echo Request to each host.
2. For non-responding hosts, try a TCP SYN to port 80 and 443.
3. For still-silent hosts, send a UDP probe to a high port and wait
   for ICMP Port Unreachable.

All three probe types run concurrently using a thread pool.  The raw
socket listener runs in a dedicated thread and feeds results back
through a thread-safe dict.

Limitations
-----------
Raw socket creation requires root / CAP_NET_RAW.  A PermissionError
is raised with an explanatory message if the process lacks that capability.
"""

import ipaddress
import os
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from .probes import icmp_echo_packet, tcp_syn, udp_probe

_ICMP_ECHO_REPLY = 0
_ICMP_DEST_UNREACH = 3
_ICMP_TTL_EXCEEDED = 11

_MAX_WORKERS    = 64
_PROBE_TIMEOUT  = 1.5     # seconds per host
_LISTEN_TIMEOUT = 0.1     # recv poll interval
_IP_HEADER_LEN  = 20


@dataclass
class HostResult:
    ip:         str
    alive:      bool        = False
    latency_ms: float       = 0.0
    open_ports: list[int]   = field(default_factory=list)
    method:     str         = ""   # "icmp" | "tcp_syn" | "udp"


def _local_source_ip(dst: str) -> str:
    """Determine which local IP would be used to reach dst."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


class DiscoveryScanner:
    """
    Sends probes to all hosts in a subnet and returns discovered hosts.

    Parameters
    ----------
    subnet : str
        CIDR notation, e.g. "192.168.1.0/24".
    timeout : float
        Seconds to wait for a reply per host.
    probe_tcp_ports : list[int]
        TCP ports tried with SYN if ICMP gets no reply.
    progress_cb : callable, optional
        Called with (done, total) after each host is probed.
    """

    def __init__(
        self,
        subnet: str,
        timeout: float = _PROBE_TIMEOUT,
        probe_tcp_ports: list[int] | None = None,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> None:
        self.network    = ipaddress.ip_network(subnet, strict=False)
        self.timeout    = timeout
        self.tcp_ports  = probe_tcp_ports or [80, 443, 22]
        self.progress   = progress_cb
        self._results:  dict[str, HostResult] = {}
        self._lock      = threading.Lock()

    def scan(self) -> list[HostResult]:
        hosts = [str(h) for h in self.network.hosts()]
        if not hosts:
            return []

        src_ip = _local_source_ip(hosts[0])

        # Open two raw sockets: one ICMP listener and one for sending
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(_LISTEN_TIMEOUT)
            tcp_recv  = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            tcp_recv.settimeout(_LISTEN_TIMEOUT)
        except PermissionError:
            raise PermissionError(
                "Raw socket creation failed. Run as root or with CAP_NET_RAW."
            ) from None

        ident = os.getpid() & 0xFFFF
        self._ident = ident

        # Start listener threads
        self._stop = threading.Event()
        listener_icmp = threading.Thread(
            target=self._listen_icmp, args=(recv_sock,), daemon=True
        )
        listener_tcp = threading.Thread(
            target=self._listen_tcp, args=(tcp_recv,), daemon=True
        )
        listener_icmp.start()
        listener_tcp.start()

        # Probe all hosts concurrently
        total = len(hosts)
        done  = 0

        with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, total)) as pool:
            futures = {
                pool.submit(self._probe_host, ip, src_ip, ident): ip
                for ip in hosts
            }
            for fut in as_completed(futures):
                fut.result()   # surface any exceptions
                done += 1
                if self.progress:
                    self.progress(done, total)

        # Let listeners drain any last packets
        time.sleep(self.timeout)
        self._stop.set()
        listener_icmp.join(timeout=1)
        listener_tcp.join(timeout=1)
        recv_sock.close()
        tcp_recv.close()

        return sorted(
            self._results.values(),
            key=lambda r: int(ipaddress.ip_address(r.ip)),
        )

    # ── probe ──────────────────────────────────────────────────────────────────

    def _probe_host(self, ip: str, src: str, ident: int) -> None:
        self._results[ip] = HostResult(ip=ip)

        # Phase 1: ICMP Echo
        t0 = self._icmp_probe(ip, src, ident)
        if t0 is not None:
            return

        # Phase 2: TCP SYN
        for port in self.tcp_ports:
            if self._tcp_syn_probe(ip, src, port):
                return

        # Phase 3: UDP
        self._udp_probe(ip, src)

    def _icmp_probe(self, ip: str, src: str, ident: int) -> float | None:
        seq = random.randint(0, 0xFFFF)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            pkt = icmp_echo_packet(src, ip, ident, seq)
            t0  = time.monotonic()
            raw_sock.sendto(pkt, (ip, 0))
        finally:
            raw_sock.close()

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            with self._lock:
                r = self._results.get(ip)
                if r and r.alive and r.method == "icmp":
                    return r.latency_ms
            time.sleep(0.01)
        return None

    def _tcp_syn_probe(self, ip: str, src: str, port: int) -> bool:
        sport = random.randint(49152, 65535)
        seq   = random.randint(0, 2**32 - 1)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            pkt = tcp_syn(src, ip, sport, port, seq)
            t0  = time.monotonic()
            raw_sock.sendto(pkt, (ip, 0))
        finally:
            raw_sock.close()

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            with self._lock:
                r = self._results.get(ip)
                if r and r.alive and r.method == "tcp_syn":
                    return True
            time.sleep(0.01)
        return False

    def _udp_probe(self, ip: str, src: str) -> None:
        sport = random.randint(49152, 65535)
        dport = random.randint(33434, 33534)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            pkt = udp_probe(src, ip, sport, dport)
            raw_sock.sendto(pkt, (ip, 0))
        finally:
            raw_sock.close()
        # No explicit wait — listener records if ICMP Port Unreachable arrives

    # ── listeners ─────────────────────────────────────────────────────────────

    def _listen_icmp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._parse_icmp(raw, addr[0])
            except Exception:
                pass

    def _parse_icmp(self, raw: bytes, src_ip: str) -> None:
        if len(raw) < _IP_HEADER_LEN + 8:
            return
        ihl = (raw[0] & 0x0F) * 4
        if len(raw) < ihl + 8:
            return
        icmp_type = raw[ihl]
        icmp_code = raw[ihl + 1]

        with self._lock:
            r = self._results.get(src_ip)
            if r is None:
                return

            if icmp_type == _ICMP_ECHO_REPLY:
                if not r.alive:
                    r.alive      = True
                    r.latency_ms = 0.0   # precise latency tracked per-probe
                    r.method     = "icmp"

            elif icmp_type == _ICMP_DEST_UNREACH:
                # ICMP Port Unreachable (code 3) means host is up, port closed
                if not r.alive:
                    r.alive  = True
                    r.method = "udp"

    def _listen_tcp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._parse_tcp(raw, addr[0])
            except Exception:
                pass

    def _parse_tcp(self, raw: bytes, src_ip: str) -> None:
        if len(raw) < _IP_HEADER_LEN + 20:
            return
        ihl = (raw[0] & 0x0F) * 4
        tcp = raw[ihl:]
        if len(tcp) < 20:
            return
        sport  = struct.unpack("!H", tcp[0:2])[0]
        flags  = struct.unpack("!H", tcp[12:14])[0] & 0x3F
        synack = 0x12   # SYN + ACK
        rst    = 0x04

        with self._lock:
            r = self._results.get(src_ip)
            if r is None:
                return
            if (flags & synack) == synack:
                r.alive = True
                r.method = "tcp_syn"
                if sport not in r.open_ports:
                    r.open_ports.append(sport)
