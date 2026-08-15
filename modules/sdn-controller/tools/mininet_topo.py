#!/usr/bin/env python3
"""
Mininet topology for testing the SDN controller.

Topology
--------
  h1 ─┐
  h2 ─┤ s1 ─── s2 ─┬─ h4
  h3 ─┘      ─── s3 ─┴─ h5
                        │
                        h6

  Three switches connected in a ring (s1–s2–s3–s1) with two hosts each.
  The ring topology exercises the spanning-tree and failover logic.

Usage
-----
  sudo python tools/mininet_topo.py
  sudo python tools/mininet_topo.py --controller 127.0.0.1 --port 6653

Requires Mininet and Open vSwitch installed.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def build_topo(controller_ip: str, controller_port: int):
    try:
        from mininet.topo import Topo
        from mininet.net import Mininet
        from mininet.node import RemoteController, OVSSwitch
        from mininet.cli import CLI
        from mininet.log import setLogLevel
    except ImportError:
        print("Mininet is not installed.  Install with: sudo apt install mininet")
        sys.exit(1)

    setLogLevel("info")

    class RingTopo(Topo):
        def build(self):
            s1 = self.addSwitch("s1", protocols="OpenFlow13")
            s2 = self.addSwitch("s2", protocols="OpenFlow13")
            s3 = self.addSwitch("s3", protocols="OpenFlow13")

            for i, sw in enumerate([s1, s2, s3], start=1):
                self.addHost(f"h{i*2-1}", ip=f"10.0.0.{i*2-1}/24")
                self.addHost(f"h{i*2}",   ip=f"10.0.0.{i*2}/24")
                self.addLink(f"h{i*2-1}", sw)
                self.addLink(f"h{i*2}",   sw)

            # Ring inter-switch links
            self.addLink(s1, s2)
            self.addLink(s2, s3)
            self.addLink(s3, s1)

    topo = RingTopo()
    ctrl = RemoteController("c0", ip=controller_ip, port=controller_port)
    net  = Mininet(topo=topo, controller=ctrl, switch=OVSSwitch)
    net.start()

    print("\n=== Topology ready ===")
    print("  Hosts: h1–h6  (10.0.0.1 – 10.0.0.6)")
    print("  Switches: s1, s2, s3 (ring)")
    print("  Controller: %s:%d" % (controller_ip, controller_port))
    print()
    print("  Try:  h1 ping h4")
    print("        h2 iperf -s &  ;  h5 iperf -c 10.0.0.2")
    print()
    CLI(net)
    net.stop()


def main():
    ap = argparse.ArgumentParser(description="Mininet ring topology for SDN controller")
    ap.add_argument("--controller", default="127.0.0.1")
    ap.add_argument("--port",       type=int, default=6653)
    args = ap.parse_args()
    build_topo(args.controller, args.port)


if __name__ == "__main__":
    main()
