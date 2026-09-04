"""Which modules are here, what they need, and how to run each on its own.

Static data. Reading it imports nothing, so `net modules` works on a host with
none of the optional dependencies installed, and a module that cannot run says
why rather than crashing the process on import.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

MODULES_ROOT = Path(__file__).resolve().parents[1] / "modules"


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    title: str
    summary: str
    package: str                 # the importable package inside the folder
    standalone: str              # how to run it from its own directory
    requires: tuple[str, ...] = ()

    @property
    def path(self) -> Path:
        return MODULES_ROOT / self.name


MANIFEST: tuple[ModuleSpec, ...] = (
    ModuleSpec(
        name="quic",
        title="QUIC transport",
        summary="Packet and frame encoding, streams with flow control, loss "
                "detection and recovery per RFC 9002.",
        package="quic",
        standalone="python tools/transfer.py",
    ),
    ModuleSpec(
        name="transport",
        title="Reliable transport over UDP",
        summary="A from-scratch reliable protocol: handshake, sequencing, "
                "selective acknowledgement, and pluggable congestion control.",
        package="ctp",
        standalone="python tools/send_file.py",
    ),
    ModuleSpec(
        name="http-benchmark",
        title="HTTP/1.1 vs /2 vs /3 benchmark",
        summary="Measures time-to-first-byte and completion under concurrency "
                "across three protocol versions against the same server.",
        package="benchmark",
        standalone="python scripts/run_benchmark.py",
        requires=("httpx",),
    ),
    ModuleSpec(
        name="topology-mapper",
        title="Network topology mapper",
        summary="Traceroute, port scanning and OS fingerprinting assembled into "
                "a graph of the reachable network.",
        package="ntm",
        standalone="python map.py 192.0.2.0/24",
    ),
    ModuleSpec(
        name="sdn-controller",
        title="SDN controller",
        summary="An OpenFlow controller: switch topology, MAC learning, "
                "shortest-path forwarding, load balancing and failover.",
        package="sdn",
        standalone="python tools/run_controller.py",
    ),
    ModuleSpec(
        name="dns",
        title="Iterative DNS resolver",
        summary="Resolves from the root servers down rather than asking a "
                "recursive resolver, with a TTL-honouring cache.",
        package="dnskit",
        standalone="python tools/resolve.py --trace example.com",
    ),
    ModuleSpec(
        name="bgp-analyzer",
        title="BGP hijack analyzer",
        summary="Parses routing updates and detects origin hijacks, sub-prefix "
                "hijacks, bogons and AS-path anomalies.",
        package="bgp_analyzer",
        standalone="python -m bgp_analyzer.cli",
    ),
)

_BY_NAME = {spec.name: spec for spec in MANIFEST}


def specs() -> list[ModuleSpec]:
    return list(MANIFEST)


def spec(name: str) -> ModuleSpec:
    try:
        return _BY_NAME[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown module {name!r}; choose from {', '.join(sorted(_BY_NAME))}"
        ) from None


def missing_requirements(spec_: ModuleSpec) -> list[str]:
    return [r for r in spec_.requires if importlib.util.find_spec(r) is None]


def add_to_path(name: str) -> Path:
    """Put one module's folder on `sys.path` — it is its own source root."""
    folder = spec(name).path
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
    return folder
