#!/usr/bin/env python3
"""
Start the SDN controller.

Usage
-----
  python tools/run_controller.py
  python tools/run_controller.py --of-port 6653 --rest-port 8080 --vip 10.0.0.100 --vport 80

REST API endpoints once running:
  GET  http://localhost:8080/topology
  GET  http://localhost:8080/switches
  GET  http://localhost:8080/lb
  GET  http://localhost:8080/macs
  GET  http://localhost:8080/failover
  POST http://localhost:8080/lb/backend   {"ip":"10.0.0.5","port":80,"mac":"00:00:00:00:00:05"}
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sdn.controller import SDNController


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    ap = argparse.ArgumentParser(description="SDN Controller")
    ap.add_argument("--of-port",   type=int, default=6653)
    ap.add_argument("--rest-port", type=int, default=8080)
    ap.add_argument("--vip",       default="10.0.0.100")
    ap.add_argument("--vport",     type=int, default=80)
    ap.add_argument("--lb-policy", default="round_robin",
                    choices=["round_robin", "least_conn"])
    args = ap.parse_args()

    ctrl = SDNController(
        of_port   = args.of_port,
        rest_port = args.rest_port,
        vip       = args.vip,
        vport     = args.vport,
        lb_policy = args.lb_policy,
    )
    ctrl.start()

    def _shutdown(sig, frame):
        print("\nShutting down …")
        ctrl.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"Controller running — OF :{args.of_port}  REST :{args.rest_port}")
    print(f"LB VIP: {args.vip}:{args.vport}  policy: {args.lb_policy}")
    print("Press Ctrl-C to stop\n")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
