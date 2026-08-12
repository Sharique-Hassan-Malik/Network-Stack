import time
import pytest

from sdn.load_balancer import LoadBalancer, Policy, Backend
from sdn.traffic_shaper import TrafficShaper, MeterBandType, MeterFlag


class TestLoadBalancerRoundRobin:
    def _lb(self):
        lb = LoadBalancer("10.0.0.100", 80, policy=Policy.ROUND_ROBIN)
        lb.add_backend("10.0.0.1", 80, "aa:aa:aa:aa:aa:01")
        lb.add_backend("10.0.0.2", 80, "aa:aa:aa:aa:aa:02")
        lb.add_backend("10.0.0.3", 80, "aa:aa:aa:aa:aa:03")
        return lb

    def test_round_robin_cycles(self):
        lb = self._lb()
        ips = [lb.get_backend("1.2.3.4", 10000 + i).ip for i in range(6)]
        assert ips[:3] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert ips[3:] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_affinity_returns_same_backend(self):
        lb = self._lb()
        b1 = lb.get_backend("1.2.3.4", 50000)
        b2 = lb.get_backend("1.2.3.4", 50000)
        assert b1 is b2

    def test_different_clients_may_use_different_backends(self):
        lb = self._lb()
        b1 = lb.get_backend("1.1.1.1", 10000)
        b2 = lb.get_backend("2.2.2.2", 10001)
        # They may differ (round-robin)
        assert b1 is not None
        assert b2 is not None

    def test_no_active_backends_returns_none(self):
        lb = LoadBalancer("10.0.0.100", 80)
        assert lb.get_backend("1.2.3.4", 9999) is None

    def test_remove_backend_evicts_flows(self):
        lb = self._lb()
        b = lb.get_backend("5.5.5.5", 12345)
        lb.remove_backend(b.ip, b.port)
        b2 = lb.get_backend("5.5.5.5", 12345)
        # After eviction a new backend is chosen
        assert b2 is not None

    def test_deactivate_reroutes_existing_flow(self):
        lb = self._lb()
        b = lb.get_backend("6.6.6.6", 55000)
        lb.set_backend_active(b.ip, b.port, False)
        b2 = lb.get_backend("6.6.6.6", 55000)
        # Either new backend or None if others also inactive
        assert b2 is None or b2.ip != b.ip

    def test_release_decrements_connection_count(self):
        lb = self._lb()
        b = lb.get_backend("7.7.7.7", 60000)
        before = b.connections
        lb.release_flow("7.7.7.7", 60000)
        assert b.connections < before or b.connections == 0

    def test_expire_removes_idle_flows(self):
        lb = LoadBalancer("10.0.0.100", 80, flow_timeout=0.05)
        lb.add_backend("10.0.0.1", 80, "aa:aa:aa:aa:aa:01")
        lb.get_backend("8.8.8.8", 1234)
        time.sleep(0.1)
        removed = lb.expire_flows()
        assert removed == 1

    def test_stats_structure(self):
        lb = self._lb()
        s = lb.stats()
        assert "vip"      in s
        assert "backends" in s
        assert s["vip"] == "10.0.0.100"


class TestLoadBalancerLeastConn:
    def test_least_conn_selects_lowest(self):
        lb = LoadBalancer("10.0.0.100", 80, policy=Policy.LEAST_CONN)
        lb.add_backend("10.0.0.1", 80, "aa:01")
        lb.add_backend("10.0.0.2", 80, "aa:02")
        lb.add_backend("10.0.0.3", 80, "aa:03")

        # Assign 2 flows to backend 1
        lb.get_backend("c1", 1000)
        lb.get_backend("c2", 1001)
        # Now backend 2 or 3 should be selected
        b = lb.get_backend("c3", 1002)
        assert b.connections <= 1

    def test_weight_affects_selection(self):
        lb = LoadBalancer("10.0.0.100", 80, policy=Policy.LEAST_CONN)
        lb.add_backend("10.0.0.1", 80, "aa:01", weight=3)
        lb.add_backend("10.0.0.2", 80, "aa:02", weight=1)
        # With same connections, weight=3 should be preferred (lower effective load)
        chosen = [lb.get_backend(f"c{i}", 2000 + i).ip for i in range(4)]
        assert chosen.count("10.0.0.1") >= chosen.count("10.0.0.2")


class TestTrafficShaper:
    def test_add_rate_limit_returns_id(self):
        ts = TrafficShaper()
        mid = ts.add_rate_limit(rate_kbps=1000)
        assert mid >= 1

    def test_ids_increment(self):
        ts = TrafficShaper()
        m1 = ts.add_rate_limit(1000)
        m2 = ts.add_rate_limit(2000)
        assert m2 > m1

    def test_get_meter_returns_meter(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(1000)
        m   = ts.get_meter(mid)
        assert m is not None
        assert m.bands[0].rate == 1000

    def test_dscp_remark_band_type(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(500, dscp_remark=True)
        m   = ts.get_meter(mid)
        assert m.bands[0].band_type == MeterBandType.DSCP_REMARK

    def test_drop_band_type(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(500)
        m   = ts.get_meter(mid)
        assert m.bands[0].band_type == MeterBandType.DROP

    def test_remove_meter(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(1000)
        ts.remove_meter(mid)
        assert ts.get_meter(mid) is None

    def test_assign_and_lookup_meter_for_flow(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(1000)
        ts.assign_meter(("10.0.0.1", "10.0.0.2", 80), mid)
        assert ts.meter_for_flow(("10.0.0.1", "10.0.0.2", 80)) == mid

    def test_meter_mod_message_type(self):
        ts  = TrafficShaper()
        mid = ts.add_rate_limit(1000)
        m   = ts.get_meter(mid)
        msg = ts.meter_mod_add(1, m)
        assert msg[1] == 29   # METER_MOD type

    def test_action_set_queue_structure(self):
        act = TrafficShaper.action_set_queue(queue_id=5)
        action_type = __import__("struct").unpack_from("!H", act)[0]
        assert action_type == 21

    def test_instruction_meter_structure(self):
        inst = TrafficShaper.instruction_meter(meter_id=3)
        inst_type = __import__("struct").unpack_from("!H", inst)[0]
        assert inst_type == 6   # OFPIT_METER

    def test_stats_structure(self):
        ts = TrafficShaper()
        ts.add_rate_limit(1000)
        s = ts.stats()
        assert "meters" in s
        assert len(s["meters"]) == 1
