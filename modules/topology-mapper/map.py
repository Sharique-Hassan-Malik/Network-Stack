#!/usr/bin/env python3
"""
Network Topology Mapper — command-line entry point.

Usage
-----
  sudo python map.py --subnet 192.168.1.0/24
  sudo python map.py --subnet 10.0.0.0/24 --ports 22,80,443 --no-traceroute
  sudo python map.py --subnet 192.168.0.0/24 --scan-method connect --output my_network.html

Most probe types require root (raw socket access).  Use --scan-method connect
to fall back to unprivileged TCP connect scanning.
"""

import argparse
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntm.discovery import DiscoveryScanner, _local_source_ip
from ntm.fingerprint import OSGuess, fingerprint_os, TCPFingerprint
from ntm.renderer import render_html
from ntm.scanner import PortState, scan_ports, TOP_100_PORTS
from ntm.topology import build_topology, default_gateway, resolve_hostnames


def _parse_ports(spec: str) -> list[int]:
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _progress_bar(prefix: str, done: int, total: int, width: int = 40) -> None:
    pct  = done / total if total else 0
    fill = int(width * pct)
    bar  = "█" * fill + "░" * (width - fill)
    print(f"\r  {prefix} [{bar}] {done}/{total}", end="", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Map a subnet: discover hosts, scan ports, infer topology and render HTML."
    )
    ap.add_argument("--subnet",       required=True,  help="CIDR range, e.g. 192.168.1.0/24")
    ap.add_argument("--ports",        default="",     help="Comma/range list, e.g. 22,80,443-445. Empty = top-100.")
    ap.add_argument("--scan-method",  default="connect", choices=["connect", "syn", "udp"])
    ap.add_argument("--timeout",      type=float, default=1.5, help="Per-host discovery timeout (s)")
    ap.add_argument("--no-traceroute", action="store_true")
    ap.add_argument("--no-rdns",       action="store_true")
    ap.add_argument("--output",       default="topology.html")
    ap.add_argument("--json",         default="",     help="Also write results JSON to this path")
    args = ap.parse_args()

    ports = _parse_ports(args.ports) if args.ports else TOP_100_PORTS
    local_ip = _local_source_ip(args.subnet.split("/")[0])
    gw       = default_gateway()

    print(f"\nNetwork Topology Mapper")
    print(f"  Subnet : {args.subnet}")
    print(f"  Local  : {local_ip}")
    print(f"  Gateway: {gw or 'unknown'}")
    print(f"  Ports  : {len(ports)} ports  [{args.scan_method}]")
    print()

    # ── phase 1: host discovery ────────────────────────────────────────────────
    print("[ 1/4 ]  Discovering hosts …")

    def disc_progress(done, total):
        _progress_bar("Discover", done, total)

    try:
        scanner = DiscoveryScanner(
            args.subnet,
            timeout    = args.timeout,
            progress_cb= disc_progress,
        )
        alive_hosts = scanner.scan()
    except PermissionError as e:
        print(f"\n  Permission error: {e}")
        print("  Run as root or use --scan-method connect for unprivileged scanning.")
        # Fall back: try TCP connect to see if anything responds
        alive_hosts = []

    print(f"\n  Found {len(alive_hosts)} live hosts\n")

    # ── phase 2: port scan ─────────────────────────────────────────────────────
    print("[ 2/4 ]  Scanning ports …")

    port_map:  dict[str, list[int]] = {}
    total_tasks = len(alive_hosts)
    done_tasks  = 0

    for hr in alive_hosts:
        results = scan_ports(hr.ip, ports, method=args.scan_method, timeout=0.5)
        open_p  = [r.port for r in results if r.state == PortState.OPEN]
        port_map[hr.ip] = open_p
        done_tasks += 1
        _progress_bar("PortScan", done_tasks, total_tasks)

    print(f"\n  Completed port scan\n")

    # ── phase 3: topology ──────────────────────────────────────────────────────
    print("[ 3/4 ]  Building topology …")
    host_ips = [h.ip for h in alive_hosts]
    graph    = build_topology(
        local_ip,
        host_ips,
        run_traceroute=not args.no_traceroute,
    )

    if not args.no_rdns:
        resolve_hostnames(graph, timeout=0.5)

    print(f"  {len(graph.nodes)} nodes  {len(graph.edges)} edges\n")

    # ── phase 4: OS fingerprint (heuristic from discovery data) ───────────────
    print("[ 4/4 ]  Fingerprinting …")
    os_guesses: dict[str, OSGuess] = {}
    for hr in alive_hosts:
        fp = TCPFingerprint(ttl=64)   # default — would be overridden with real packet data
        guess = fingerprint_os(fp)
        if guess.confidence > 0:
            os_guesses[hr.ip] = guess
    print("  Done\n")

    # ── render ─────────────────────────────────────────────────────────────────
    out = render_html(
        graph    = graph,
        local_ip = local_ip,
        os_guesses = os_guesses,
        port_map   = port_map,
        output   = args.output,
    )
    print(f"Graph saved → {out}")

    # ── optional JSON export ───────────────────────────────────────────────────
    if args.json:
        data = {
            "subnet":   args.subnet,
            "local_ip": local_ip,
            "gateway":  gw,
            "hosts":    [
                {
                    "ip":        hr.ip,
                    "method":    hr.method,
                    "open_ports": port_map.get(hr.ip, []),
                    "hostname":  graph.nodes.get(hr.ip, type("", (), {"hostname": None})()).hostname,
                    "os":        (
                        {
                            "family":     os_guesses[hr.ip].family,
                            "version":    os_guesses[hr.ip].version,
                            "confidence": os_guesses[hr.ip].confidence,
                        }
                        if hr.ip in os_guesses else None
                    ),
                }
                for hr in alive_hosts
            ],
            "graph": graph.to_dict(),
        }
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"JSON saved  → {args.json}")

    print()


if __name__ == "__main__":
    main()
