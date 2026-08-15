"""A bottleneck link, so the congestion controllers can be compared.

Sharing the controllers between two transports is only worth something if you
can tell them apart. This is the smallest thing that does: a fixed-bandwidth,
fixed-delay link with a finite queue and a loss rate, driven in round-trip
steps.

It is a model, not a network. There is no reordering, no competing flow, no
variable delay, and time advances in whole RTTs. What it does capture is the
one behaviour that separates these algorithms: how each one responds to a
queue filling and to a loss signal. Numbers from it describe the controller,
not your network.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .congestion import build
from .measure import Measurement, Run


@dataclass
class Link:
    """A bottleneck: bandwidth, base delay, queue depth, and random loss."""

    bandwidth_bps: float = 10e6        # 10 Mbit/s
    base_rtt: float = 0.05             # 50 ms
    queue_bytes: int = 64 * 1024
    loss_rate: float = 0.0
    mss: int = 1400

    @property
    def bdp(self) -> float:
        """Bandwidth-delay product — the window that exactly fills the pipe."""
        return self.bandwidth_bps * self.base_rtt / 8.0

    def deliver(self, inflight_bytes: float, rng: random.Random) -> tuple[float, float, bool]:
        """One round trip.

        Returns (bytes delivered, observed RTT, whether loss occurred).

        Queueing delay is the part that matters: sending more than the pipe
        holds does not go faster, it just adds latency — which is why a
        loss-based controller and a model-based one end up in different places.
        """
        capacity = self.bdp
        queued = max(0.0, inflight_bytes - capacity)
        overflow = max(0.0, queued - self.queue_bytes)

        queue_delay = min(queued, self.queue_bytes) * 8.0 / self.bandwidth_bps
        rtt = self.base_rtt + queue_delay

        lost = overflow > 0 or (self.loss_rate > 0 and rng.random() < self.loss_rate)
        # What the pipe carried this round. Bytes that overflowed the queue
        # were dropped before they were ever in flight — they are the loss
        # signal, not a reduction in throughput.
        delivered = min(inflight_bytes, capacity)
        return max(delivered, 0.0), rtt, lost


def compare(
    algorithms: tuple[str, ...] = ("reno", "cubic", "bbr"),
    *,
    link: Link | None = None,
    rounds: int = 400,
    seed: int = 0,
) -> Run:
    """Drive each controller over the same link and report what it achieved.

    Every algorithm sees the same link and the same loss draw — the random
    generator is reseeded per algorithm — so a difference in the result is a
    difference in the algorithm.
    """
    link = link or Link()
    run = Run(tool="congestion-compare", target=f"{link.bandwidth_bps/1e6:g} Mbit/s, "
                                                f"{link.base_rtt*1000:g} ms RTT")

    throughput = run.measure("throughput", unit="Mbit/s")
    latency = run.measure("rtt", unit="ms")

    for algorithm in algorithms:
        rng = random.Random(seed)

        # Simulated time, so the time-driven controllers advance with the
        # simulation rather than with the wall clock.
        elapsed = 0.0
        controller = build(algorithm, mss=link.mss, clock=lambda: elapsed)

        delivered_total = 0.0
        rtts: list[float] = []

        for _ in range(rounds):
            inflight = float(controller.cwnd)
            delivered, rtt, lost = link.deliver(inflight, rng)

            delivered_total += delivered
            elapsed += rtt
            rtts.append(rtt)

            if lost:
                controller.on_loss()
            else:
                controller.on_ack(int(delivered), rtt)

        mbps = (delivered_total * 8.0 / elapsed) / 1e6 if elapsed else 0.0
        mean_rtt = sum(rtts) / len(rtts) * 1000

        throughput.add(mbps)
        latency.add(mean_rtt)
        run.facts[algorithm] = {
            "throughput_mbps": round(mbps, 3),
            "mean_rtt_ms": round(mean_rtt, 2),
            "final_cwnd_bytes": int(controller.cwnd),
            # Utilisation above 100% is impossible; below it means the
            # controller left capacity unused.
            "link_utilisation": round(min(mbps / (link.bandwidth_bps / 1e6), 1.0), 3),
        }

    return run
