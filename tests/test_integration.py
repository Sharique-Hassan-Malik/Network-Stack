"""Cross-module tests — the guarantees that come from sharing a core.

Each module's own behaviour is tested in its own folder. What is tested here is
that the shared estimator and controllers behave identically for every consumer,
that the protocols' numbers are unchanged by going through them, and that each
module still runs from its own directory.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from netcore import registry  # noqa: E402
from netcore.congestion import BBR, CONTROLLERS, CUBIC, CongestionController, Reno, build  # noqa: E402
from netcore.measure import Measurement, Report, Run, percentile  # noqa: E402
from netcore.rtt import ALPHA, BETA, K, RTTEstimator  # noqa: E402
from netcore.simulate import Link, compare  # noqa: E402


class TestLayout:
    def test_every_declared_module_exists(self):
        for spec in registry.specs():
            assert spec.path.is_dir(), f"{spec.name} is missing"

    def test_every_module_has_a_readme_and_tests(self):
        for spec in registry.specs():
            assert (spec.path / "README.md").is_file(), f"{spec.name} has no README"
            assert (spec.path / "tests").is_dir(), f"{spec.name} ships no tests"

    def test_every_module_package_is_importable_from_its_own_folder(self):
        for spec in registry.specs():
            assert (spec.path / spec.package).is_dir() or \
                   (spec.path / f"{spec.package}.py").is_file(), \
                   f"{spec.name} has no {spec.package} package"

    def test_unknown_module_is_a_clear_error(self):
        with pytest.raises(KeyError, match="unknown module"):
            registry.spec("nope")


class TestSharedRtt:
    def test_rfc6298_constants_are_the_published_ones(self):
        assert (ALPHA, BETA, K) == (0.125, 0.25, 4)

    def test_first_sample_seeds_srtt_and_variance(self):
        estimator = RTTEstimator()
        estimator.update(0.1)
        assert estimator.smoothed == pytest.approx(0.1)
        assert estimator.rttvar == pytest.approx(0.05)
        assert estimator.rto == pytest.approx(0.3, rel=1e-3)

    def test_converges_towards_a_steady_sample(self):
        estimator = RTTEstimator()
        for _ in range(60):
            estimator.update(0.05)
        assert estimator.smoothed == pytest.approx(0.05, rel=0.02)
        assert estimator.rttvar < 0.005

    def test_ack_delay_never_drives_srtt_below_anything_observed(self):
        """A peer that over-reports its delay must not corrupt the estimate."""
        estimator = RTTEstimator(max_ack_delay=0.025)
        estimator.update(0.100)
        estimator.update(0.100, ack_delay=0.500)     # implausible report
        assert estimator.smoothed >= estimator.min_rtt

    def test_backoff_doubles_and_a_sample_clears_it(self):
        estimator = RTTEstimator()
        estimator.update(0.1)
        before = estimator.rto

        estimator.backoff()
        assert estimator.rto == pytest.approx(before * 2, rel=1e-6)

        # A fresh sample clears the backoff. The RTO does not return to its
        # exact previous value, and should not: a second agreeing sample
        # shrinks RTTVAR, so the timeout legitimately tightens.
        estimator.update(0.1)
        expected = estimator.smoothed + K * estimator.rttvar
        assert estimator.rto == pytest.approx(expected, rel=1e-6)
        assert estimator.rto < before * 2

    def test_rto_is_bounded_both_ways(self):
        fast = RTTEstimator()
        fast.update(0.000001)
        assert fast.rto >= RTTEstimator.MIN_RTO

        slow = RTTEstimator()
        for _ in range(20):
            slow.update(120.0)
        assert slow.rto <= RTTEstimator.MAX_RTO


class TestSharedCongestion:
    @pytest.mark.parametrize("name", sorted(CONTROLLERS))
    def test_every_controller_satisfies_the_interface(self, name):
        controller = build(name, mss=1200)
        assert isinstance(controller, CongestionController)
        assert controller.cwnd > 0

    @pytest.mark.parametrize("name", sorted(CONTROLLERS))
    def test_loss_never_opens_the_window(self, name):
        """The one property all three share.

        Growth is not: Reno and CUBIC increase additively on every ack, while
        BBR targets the bandwidth-delay product and will *reduce* cwnd when it
        probes for the minimum RTT. Asserting growth for all three would be
        asserting that BBR is a loss-based controller.
        """
        controller = build(name, mss=1200, clock=_ticking())
        for _ in range(30):
            controller.on_ack(1200, 0.05)
        before_loss = controller.cwnd
        controller.on_loss()
        assert 0 < controller.cwnd <= before_loss

    @pytest.mark.parametrize("name", ["reno", "cubic"])
    def test_loss_based_controllers_grow_on_acks(self, name):
        controller = build(name, mss=1200)
        start = controller.cwnd
        for _ in range(30):
            controller.on_ack(1200, 0.05)
        assert controller.cwnd > start

    def test_unknown_algorithm_names_the_alternatives(self):
        with pytest.raises(ValueError, match="reno"):
            build("vegas")

    def test_an_option_no_controller_accepts_is_an_error(self):
        with pytest.raises(TypeError):
            build("reno", nonsense=1)

    def test_an_option_only_some_accept_is_dropped_not_raised(self):
        """`clock` is meaningful for the time-driven controllers only."""
        assert isinstance(build("reno", clock=lambda: 0.0), Reno)
        assert isinstance(build("bbr", clock=lambda: 0.0), BBR)

    def test_reno_reduces_once_per_recovery_epoch(self):
        reno = Reno(mss=1200)
        for _ in range(30):
            reno.on_ack(1200)
        assert reno.on_loss_at(sent_at=10.0, now=10.0) is True
        after_first = reno.cwnd
        # A second loss from a packet sent before the epoch must not halve again.
        assert reno.on_loss_at(sent_at=9.0, now=11.0) is False
        assert reno.cwnd == after_first


class TestBothTransportsUseTheCore:
    def test_quic_recovery_uses_the_shared_estimator(self):
        registry.add_to_path("quic")
        from quic.recovery import RecoveryManager

        manager = RecoveryManager()
        assert isinstance(manager.rtt, RTTEstimator)
        manager.update_rtt(0.08)
        assert manager.srtt == pytest.approx(0.08)

    @pytest.mark.parametrize("algorithm", ["reno", "cubic", "bbr"])
    def test_quic_accepts_every_controller(self, algorithm):
        """The capability QUIC gained: its congestion control is now a seam."""
        registry.add_to_path("quic")
        from quic.recovery import RecoveryManager

        manager = RecoveryManager(congestion=algorithm)
        assert manager.cwnd > 0
        manager.update_rtt(0.05)
        manager.congestion.on_ack(1200, 0.05)
        assert manager.cwnd > 0

    def test_transport_re_exports_resolve_to_the_shared_classes(self):
        registry.add_to_path("transport")
        from ctp.congestion import BBR as CtpBBR, CUBIC as CtpCUBIC
        from ctp.rtt import RTTEstimator as CtpEstimator

        assert CtpBBR is BBR
        assert CtpCUBIC is CUBIC
        assert CtpEstimator is RTTEstimator


class TestMeasurement:
    def test_percentiles_interpolate(self):
        values = list(range(1, 11))
        assert percentile(values, 50) == pytest.approx(5.5)
        assert percentile(values, 99) == pytest.approx(9.91)

    def test_the_old_index_arithmetic_under_reported_the_tail(self):
        """Guards the bug that the shared definition fixed."""
        values = list(range(1, 11))
        old = sorted(values)[max(0, int(len(values) * 99 / 100) - 1)]
        assert old == 9
        assert percentile(values, 99) > old

    def test_empty_series_is_zero_not_an_error(self):
        assert Measurement("empty").p99 == 0.0

    def test_summary_carries_the_shape_of_the_distribution(self):
        measurement = Measurement("latency", unit="ms")
        measurement.extend([10, 20, 30, 40, 1000])
        summary = measurement.summary()
        assert summary["count"] == 5
        assert summary["max"] == 1000
        assert summary["p50"] == 30

    def test_report_serialises(self):
        report = Report(title="t")
        run = report.add(Run(tool="x", target="y"))
        run.measure("latency").extend([1, 2, 3])
        assert "latency" in report.to_json()


class TestSimulation:
    def test_every_algorithm_moves_data(self):
        run = compare(link=Link(), rounds=120)
        for algorithm, facts in run.facts.items():
            assert facts["throughput_mbps"] > 0, algorithm
            assert 0 < facts["link_utilisation"] <= 1.0

    def test_bbr_keeps_the_queue_shorter_than_the_loss_based_controllers(self):
        """BBR targets the bandwidth-delay product rather than filling the queue,
        so it should sit at a lower RTT than Reno or CUBIC on the same link."""
        run = compare(link=Link(loss_rate=0.0), rounds=300)
        assert run.facts["bbr"]["mean_rtt_ms"] < run.facts["reno"]["mean_rtt_ms"]
        assert run.facts["bbr"]["mean_rtt_ms"] < run.facts["cubic"]["mean_rtt_ms"]

    def test_the_run_is_reproducible(self):
        first = compare(link=Link(loss_rate=0.05), rounds=100, seed=7).facts
        second = compare(link=Link(loss_rate=0.05), rounds=100, seed=7).facts
        assert first == second


class TestStandalone:
    """Each module runs from its own folder — the reason for the layout."""

    HELP = {
        "topology-mapper": [sys.executable, "map.py", "--help"],
        "bgp-analyzer": [sys.executable, "-m", "bgp_analyzer.cli", "--help"],
    }

    @pytest.mark.parametrize("name", sorted(HELP))
    def test_cli_runs_from_its_own_folder(self, name):
        completed = subprocess.run(
            self.HELP[name], cwd=registry.spec(name).path,
            capture_output=True, text=True, timeout=180,
        )
        assert completed.returncode == 0, completed.stderr

    def test_transport_imports_the_core_with_nothing_installed(self):
        completed = subprocess.run(
            [sys.executable, "-c",
             "from ctp.congestion import BBR; from ctp.rtt import RTTEstimator;"
             "print(BBR.__module__, RTTEstimator.__module__)"],
            cwd=registry.spec("transport").path,
            capture_output=True, text=True, timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        assert "netcore" in completed.stdout


class TestCli:
    def test_modules_listing_covers_the_repo(self, capsys):
        from netcore import cli

        assert cli.main(["modules"]) == 0
        out = capsys.readouterr().out
        for spec in registry.specs():
            assert spec.name in out

    def test_congestion_comparison_prints_every_algorithm(self, capsys):
        from netcore import cli

        assert cli.main(["congestion", "--rounds", "60"]) == 0
        out = capsys.readouterr().out
        for algorithm in ("reno", "cubic", "bbr"):
            assert algorithm in out


def _ticking():
    """A clock that advances 50 ms per read, for the time-driven controllers."""
    state = {"t": 0.0}

    def clock() -> float:
        state["t"] += 0.05
        return state["t"]

    return clock
