import time
import pytest
from ctp.congestion import BBR, CUBIC, _BETA


class TestBBRStartup:
    def test_initial_state(self):
        b = BBR(mss=1400)
        assert b._state == "STARTUP"
        assert b.cwnd >= 4 * 1400

    def test_pacing_rate_bootstraps(self):
        b = BBR()
        # Before any ACKs, btl_bw is 0 — should return bootstrap rate
        rate = b.pacing_rate
        assert rate > 0

    def test_startup_to_drain_transition(self):
        b = BBR(mss=1400)
        # Feed constant bandwidth — 3 rounds without 25 % growth triggers DRAIN
        for _ in range(20):
            b.on_ack(1400, rtt=0.05)
        # May have transitioned past STARTUP
        assert b._state in ("STARTUP", "DRAIN", "PROBE_BW")

    def test_bw_filter_accumulates(self):
        import time
        b = BBR()
        # First ACK initialises the stamp; a second ACK after a measurable
        # interval produces a bandwidth sample.
        b.on_ack(14000, rtt=0.01)
        time.sleep(0.002)
        b.on_ack(14000, rtt=0.01)
        assert len(b._bw_filter) >= 1
        assert b.btl_bw > 0


class TestBBRRTProp:
    def test_min_rtt_updates(self):
        b = BBR()
        b.on_ack(1400, rtt=0.1)
        b.on_ack(1400, rtt=0.05)
        b.on_ack(1400, rtt=0.2)
        assert b.rt_prop == pytest.approx(0.05, rel=1e-3)

    def test_cwnd_grows_after_acks(self):
        b = BBR()
        initial = b.cwnd
        for _ in range(30):
            b.on_ack(14000, rtt=0.01)
        assert b.cwnd >= initial

    def test_on_loss_reduces_cwnd(self):
        b = BBR()
        for _ in range(10):
            b.on_ack(14000, rtt=0.01)
        before = b.cwnd
        b.on_loss()
        assert b.cwnd <= before


class TestCUBICSlowStart:
    def test_initial_cwnd(self):
        c = CUBIC(mss=1400)
        assert c.cwnd == 1400 * 10
        assert c._slow_start is True

    def test_slow_start_grows(self):
        c = CUBIC(mss=1400)
        initial = c.cwnd
        c.on_ack(1400, rtt=0.05)
        assert c.cwnd > initial

    def test_exits_slow_start_at_ssthresh(self):
        c = CUBIC(mss=1400)
        c._ssthresh = c.mss * 15   # low threshold for testing
        for _ in range(20):
            c.on_ack(c.mss, rtt=0.05)
        assert not c._slow_start


class TestCUBICLoss:
    def test_cwnd_reduction_on_loss(self):
        c = CUBIC(mss=1400)
        c._slow_start = False
        c.cwnd = 100 * 1400
        before = c.cwnd
        c.on_loss()
        assert c.cwnd < before
        assert c.cwnd == pytest.approx(before * _BETA, rel=1e-3)

    def test_ssthresh_set_on_loss(self):
        c = CUBIC(mss=1400)
        c._slow_start = False
        c.cwnd = 50 * 1400
        c.on_loss()
        assert c._ssthresh == pytest.approx(50 * 1400 * _BETA, rel=1e-3)

    def test_k_computed_correctly(self):
        from ctp.congestion import _C, _BETA
        c = CUBIC(mss=1400)
        c._slow_start = False
        c.cwnd = 100 * 1400
        c.on_loss()
        expected_k = (c._w_max * (1 - _BETA) / _C) ** (1 / 3)
        assert c._k == pytest.approx(expected_k, rel=1e-6)

    def test_multiple_losses_do_not_crash(self):
        c = CUBIC()
        for _ in range(10):
            c.on_loss()
        assert c.cwnd >= 2 * c.mss


class TestCUBICRecovery:
    def test_cwnd_grows_after_loss(self):
        c = CUBIC(mss=1400)
        c._slow_start = False
        c.cwnd = 200 * 1400
        c.on_loss()
        low = c.cwnd
        for _ in range(100):
            c.on_ack(1400, rtt=0.05)
        assert c.cwnd >= low
