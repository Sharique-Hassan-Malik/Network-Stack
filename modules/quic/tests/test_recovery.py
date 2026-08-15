import time
import pytest

from quic.recovery import (
    RecoveryManager, SentPacket, PacketNumberSpace,
    K_INITIAL_RTT, K_INITIAL_WINDOW, K_MINIMUM_WINDOW,
)


class TestPacketNumberSpace:
    def test_allocate_sequential(self):
        ns = PacketNumberSpace()
        assert ns.allocate_pn() == 0
        assert ns.allocate_pn() == 1
        assert ns.allocate_pn() == 2

    def test_on_packet_sent_tracked(self):
        ns = PacketNumberSpace()
        pn = ns.allocate_pn()
        ns.on_packet_sent(pn, 100, in_flight=True, frames=[])
        assert pn in ns.sent
        assert ns.sent[pn].size == 100
        assert ns.ack_eliciting_in_flight == 1

    def test_non_inflight_not_counted(self):
        ns = PacketNumberSpace()
        pn = ns.allocate_pn()
        ns.on_packet_sent(pn, 50, in_flight=False, frames=[])
        assert ns.ack_eliciting_in_flight == 0


class TestRecoveryManagerRTT:
    def test_initial_values(self):
        rm = RecoveryManager()
        assert rm.srtt == K_INITIAL_RTT
        assert rm.cwnd == K_INITIAL_WINDOW

    def test_rtt_update_first_sample(self):
        rm = RecoveryManager()
        rm.update_rtt(0.050)
        assert rm.srtt == pytest.approx(0.050, rel=0.05)

    def test_rtt_converges(self):
        rm = RecoveryManager()
        for _ in range(30):
            rm.update_rtt(0.020)
        assert rm.srtt == pytest.approx(0.020, rel=0.1)

    def test_rto_positive(self):
        rm = RecoveryManager()
        rm.update_rtt(0.05)
        assert rm.rto > 0


class TestRecoveryManagerACK:
    def test_ack_removes_inflight(self):
        rm  = RecoveryManager()
        ns  = rm.spaces["app"]
        pn  = ns.allocate_pn()
        ns.on_packet_sent(pn, 1200, True, [])
        rm.bytes_in_flight = 1200

        newly, lost = rm.on_ack_received("app", pn, 0, [(pn, pn)])
        assert len(newly) == 1
        assert newly[0].pn == pn
        assert rm.bytes_in_flight == 0

    def test_duplicate_ack_ignored(self):
        rm = RecoveryManager()
        ns = rm.spaces["app"]
        pn = ns.allocate_pn()
        ns.on_packet_sent(pn, 100, True, [])
        rm.bytes_in_flight = 100

        rm.on_ack_received("app", pn, 0, [(pn, pn)])
        newly, _ = rm.on_ack_received("app", pn, 0, [(pn, pn)])
        assert len(newly) == 0

    def test_ack_range_covers_multiple(self):
        rm = RecoveryManager()
        ns = rm.spaces["app"]
        for _ in range(5):
            pn = ns.allocate_pn()
            ns.on_packet_sent(pn, 100, True, [])
        rm.bytes_in_flight = 500

        newly, _ = rm.on_ack_received("app", 4, 0, [(0, 4)])
        assert len(newly) == 5
        assert rm.bytes_in_flight == 0

    def test_cwnd_grows_in_slow_start(self):
        rm = RecoveryManager()
        ns = rm.spaces["app"]
        rm.bytes_in_flight = 0

        pn = ns.allocate_pn()
        ns.on_packet_sent(pn, 1200, True, [])
        rm.bytes_in_flight = 1200
        before = rm.cwnd

        rm.on_ack_received("app", pn, 0, [(pn, pn)])
        assert rm.cwnd >= before


class TestRecoveryManagerLoss:
    def test_packet_after_3_newer_acks_is_lost(self):
        rm = RecoveryManager()
        ns = rm.spaces["app"]

        for i in range(5):
            pn = ns.allocate_pn()
            ns.on_packet_sent(pn, 100, True, [])
        rm.bytes_in_flight = 500
        ns.largest_acked   = 4

        # Manually mark pn=0 old enough
        ns.sent[0].sent_at -= 1.0

        _, lost = rm.on_ack_received("app", 4, 0, [(1, 4)])
        lost_pns = [p.pn for p in lost]
        assert 0 in lost_pns

    def test_congestion_event_reduces_cwnd(self):
        rm  = RecoveryManager()
        rm.cwnd            = K_INITIAL_WINDOW
        rm.bytes_in_flight = K_INITIAL_WINDOW
        rm._on_congestion_event(time.monotonic() - 1)
        assert rm.cwnd <= K_INITIAL_WINDOW
        assert rm.cwnd >= K_MINIMUM_WINDOW


class TestPTO:
    def test_no_inflight_no_pto(self):
        rm = RecoveryManager()
        assert not rm.pto_expired("app")

    def test_pto_fires_after_timeout(self):
        rm = RecoveryManager()
        ns = rm.spaces["app"]
        pn = ns.allocate_pn()
        ns.on_packet_sent(pn, 100, True, [])
        rm.bytes_in_flight = 100

        # Artificially age the packet
        ns.sent[pn].sent_at -= 100.0
        assert rm.pto_expired("app")

    def test_pto_count_increments(self):
        rm = RecoveryManager()
        before = rm._pto_count
        rm.on_pto_fired()
        assert rm._pto_count == before + 1
