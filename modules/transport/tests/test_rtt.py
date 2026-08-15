import pytest
from ctp.rtt import RTTEstimator


class TestRTTFirstSample:
    def test_initial_rto(self):
        r = RTTEstimator()
        assert r.rto == 1.0

    def test_first_update_sets_srtt(self):
        r = RTTEstimator()
        r.update(0.1)
        assert r.srtt == pytest.approx(0.1)

    def test_rto_after_first_sample(self):
        r = RTTEstimator()
        r.update(0.1)
        # rto = srtt + 4 * rttvar = 0.1 + 4 * 0.05 = 0.3
        assert r.rto == pytest.approx(0.3, rel=1e-3)


class TestRTTConvergence:
    def test_stable_rtt(self):
        r = RTTEstimator()
        for _ in range(50):
            r.update(0.05)
        assert r.srtt == pytest.approx(0.05, rel=0.05)

    def test_rto_bounded_below(self):
        r = RTTEstimator()
        for _ in range(20):
            r.update(0.001)
        assert r.rto >= RTTEstimator.MIN_RTO

    def test_rto_bounded_above(self):
        r = RTTEstimator()
        r.update(100.0)
        assert r.rto <= RTTEstimator.MAX_RTO


class TestBackoff:
    def test_backoff_doubles_rto(self):
        r = RTTEstimator()
        r.update(0.2)
        before = r.rto
        r.backoff()
        assert r.rto == pytest.approx(before * 2, rel=1e-6)

    def test_multiple_backoffs_cap_at_max(self):
        r = RTTEstimator()
        r.update(0.5)
        for _ in range(20):
            r.backoff()
        assert r.rto == RTTEstimator.MAX_RTO

    def test_reset_backoff_recalculates(self):
        r = RTTEstimator()
        r.update(0.1)
        r.backoff()
        r.backoff()
        before_reset = r.rto
        r.reset_backoff()
        assert r.rto < before_reset
        assert r.rto >= RTTEstimator.MIN_RTO
