"""
Traffic shaping and rate limiting.

Two mechanisms are implemented:

  1. Flow-level rate limiting via OpenFlow Meter tables (OF 1.3 §5.7).
     Each flow can be assigned a meter that drops or marks packets exceeding
     a token-bucket rate.

  2. Per-switch queue allocation using OF 1.3 QUEUE_MOD (simplified: the
     controller tracks desired queues and emits SET_QUEUE actions in flow
     entries so the switch forwards on the correct queue).

The TrafficShaper object is the central registry.  The controller consults
it when installing flow entries to decide whether a meter or queue action
should be appended.

Meter wire format (OF 1.3 §7.3.4.4):
  METER_MOD = type 29
  Meter bands: OFPMBT_DROP = 1, OFPMBT_DSCP_REMARK = 2
"""

from __future__ import annotations

import struct
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class MeterBandType(IntEnum):
    DROP        = 1
    DSCP_REMARK = 2


class MeterFlag(IntEnum):
    KBPS   = 1
    PKTPS  = 2
    BURST  = 4
    STATS  = 8


@dataclass
class MeterBand:
    band_type:    MeterBandType
    rate:         int           # kbps or pktps
    burst_size:   int           = 0
    prec_level:   int           = 0   # DSCP remark only


@dataclass
class Meter:
    meter_id:  int
    flags:     int
    bands:     list[MeterBand] = field(default_factory=list)


@dataclass
class QueueConfig:
    queue_id:  int
    port:      int
    min_rate:  int   = 0       # kbps; 0 = no minimum
    max_rate:  int   = 0       # kbps; 0 = no maximum


class TrafficShaper:
    """
    Registry of meter and queue configurations.

    The controller installs meters on switches when a flow rule is
    associated with a rate limit.  Queue configs drive SET_QUEUE
    actions appended to flow entries.
    """

    def __init__(self) -> None:
        self._meters: dict[int, Meter]       = {}   # meter_id → Meter
        self._queues: dict[tuple, QueueConfig] = {}   # (dpid, port, queue_id)
        self._flow_meters: dict[tuple, int]  = {}   # flow_key → meter_id
        self._lock = threading.Lock()
        self._next_meter = 1

    # ── meters ────────────────────────────────────────────────────────────────

    def add_rate_limit(
        self,
        rate_kbps:   int,
        burst_kbps:  int = 0,
        dscp_remark: bool = False,
    ) -> int:
        """
        Create a meter and return its ID.

        Parameters
        ----------
        rate_kbps : int
            Maximum allowed rate in kbps.
        burst_kbps : int
            Burst allowance.
        dscp_remark : bool
            If True use DSCP_REMARK instead of DROP.
        """
        with self._lock:
            mid = self._next_meter
            self._next_meter += 1
            band_type = MeterBandType.DSCP_REMARK if dscp_remark else MeterBandType.DROP
            band = MeterBand(band_type=band_type, rate=rate_kbps, burst_size=burst_kbps)
            flags = MeterFlag.KBPS | MeterFlag.STATS
            if burst_kbps:
                flags |= MeterFlag.BURST
            self._meters[mid] = Meter(meter_id=mid, flags=flags, bands=[band])
            return mid

    def remove_meter(self, meter_id: int) -> None:
        with self._lock:
            self._meters.pop(meter_id, None)
            self._flow_meters = {k: v for k, v in self._flow_meters.items()
                                 if v != meter_id}

    def assign_meter(self, flow_key: tuple, meter_id: int) -> None:
        with self._lock:
            self._flow_meters[flow_key] = meter_id

    def meter_for_flow(self, flow_key: tuple) -> Optional[int]:
        with self._lock:
            return self._flow_meters.get(flow_key)

    def get_meter(self, meter_id: int) -> Optional[Meter]:
        with self._lock:
            return self._meters.get(meter_id)

    # ── queues ────────────────────────────────────────────────────────────────

    def add_queue(self, dpid: int, port: int, queue_id: int,
                  min_rate: int = 0, max_rate: int = 0) -> None:
        with self._lock:
            self._queues[(dpid, port, queue_id)] = QueueConfig(
                queue_id=queue_id, port=port, min_rate=min_rate, max_rate=max_rate
            )

    def queue_config(self, dpid: int, port: int, queue_id: int) -> Optional[QueueConfig]:
        with self._lock:
            return self._queues.get((dpid, port, queue_id))

    # ── OF wire messages ──────────────────────────────────────────────────────

    @staticmethod
    def meter_mod_add(xid: int, meter: Meter) -> bytes:
        """Serialise an OFPT_METER_MOD (type=29, command=ADD=0) message."""
        bands = b""
        for band in meter.bands:
            if band.band_type == MeterBandType.DROP:
                bands += struct.pack("!HHII", int(MeterBandType.DROP), 16,
                                     band.rate, band.burst_size)
            else:
                bands += struct.pack("!HHIIB3x", int(MeterBandType.DSCP_REMARK), 16,
                                     band.rate, band.burst_size, band.prec_level)

        body  = struct.pack("!HHI", meter.flags, 0, meter.meter_id) + bands
        total = 8 + len(body)
        return struct.pack("!BBHI", 0x04, 29, total, xid) + body

    @staticmethod
    def action_set_queue(queue_id: int) -> bytes:
        """OFPAT_SET_QUEUE action (type=21)."""
        return struct.pack("!HHI", 21, 8, queue_id)

    @staticmethod
    def instruction_meter(meter_id: int) -> bytes:
        """OFPIT_METER instruction (type=6)."""
        return struct.pack("!HHI", 6, 8, meter_id)

    # ── stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            return {
                "meters": [
                    {
                        "id":    m.meter_id,
                        "flags": m.flags,
                        "bands": [
                            {
                                "type":       b.band_type.name,
                                "rate_kbps":  b.rate,
                                "burst_kbps": b.burst_size,
                            }
                            for b in m.bands
                        ],
                    }
                    for m in self._meters.values()
                ],
                "flow_meters": len(self._flow_meters),
                "queues":      len(self._queues),
            }
