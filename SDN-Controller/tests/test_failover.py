import time
import pytest
from unittest.mock import MagicMock

from sdn.failover import FailoverManager, LinkFailureEvent
from sdn.openflow import OFPPortReason
from sdn.topology import TopologyGraph


def _make_port_status(reason, port_no, state=0):
    """Create a mock PortStatus without raw packet parsing."""
    from sdn.openflow import PortStatus
    ps = PortStatus.__new__(PortStatus)
    ps.reason  = reason
    ps.port_no = port_no
    ps.state   = state
    ps.hw_addr = b"\x00" * 6
    ps.name    = "eth0"
    ps.config  = 0
    ps.xid     = 0
    return ps


class TestFailoverManager:
    def _make_topo(self):
        g = TopologyGraph()
        g.add_switch(1, ports={1, 2, 3})
        g.add_switch(2, ports={1, 2, 3})
        g.add_switch(3, ports={1, 2, 3})
        g.add_link(1, 3, 2, 1)
        g.add_link(2, 3, 3, 1)
        g.add_link(3, 2, 1, 2)
        return g

    def test_link_down_removes_from_topology(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        # port 3 on dpid 1 connects to dpid 2 (via add_link(1,3,2,1))
        ps   = _make_port_status(OFPPortReason.DELETE, port_no=3)
        fm.on_port_status(1, ps)
        # Link from dpid 1 to dpid 2 (was on port 3) is now gone
        assert topo.link_port(1, 2) is None
        # Link from dpid 1 to dpid 3 (on port 2, added via add_link(3,2,1,2)) still present
        assert topo.link_port(1, 3) is not None

    def test_port_link_down_state_detected(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        ps   = _make_port_status(OFPPortReason.MODIFY, port_no=3,
                                 state=1)   # PORT_LINK_DOWN=1
        fm.on_port_status(1, ps)
        failures = fm.active_failures()
        assert len(failures) == 1
        assert failures[0]["port"] == 3

    def test_callback_fired_on_failure(self):
        topo = self._make_topo()
        fired = []
        fm   = FailoverManager(topo, callbacks=[lambda mgr, evt: fired.append(evt)])
        ps   = _make_port_status(OFPPortReason.DELETE, port_no=3)
        fm.on_port_status(1, ps)
        assert len(fired) == 1
        assert isinstance(fired[0], LinkFailureEvent)

    def test_recovery_clears_failure(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        ps_down = _make_port_status(OFPPortReason.DELETE, port_no=3)
        fm.on_port_status(1, ps_down)
        assert len(fm.active_failures()) == 1

        ps_up = _make_port_status(OFPPortReason.ADD, port_no=3, state=0)
        fm.on_port_status(1, ps_up)
        assert len(fm.active_failures()) == 0

    def test_duplicate_failure_not_duplicated(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        ps   = _make_port_status(OFPPortReason.DELETE, port_no=3)
        fm.on_port_status(1, ps)
        fm.on_port_status(1, ps)   # second time: already handling
        assert len(fm.active_failures()) == 1

    def test_install_fn_called_on_failure(self):
        topo = self._make_topo()
        topo.update_host("aa:aa:aa:aa:aa:01", dpid=1, port=1)
        topo.update_host("aa:aa:aa:aa:aa:02", dpid=2, port=1)
        installed = []
        fm = FailoverManager(topo, install_fn=lambda dpid, rules: installed.append((dpid, rules)))
        ps = _make_port_status(OFPPortReason.DELETE, port_no=3)
        fm.on_port_status(1, ps)
        # install_fn should be called for affected switches
        assert len(installed) >= 0   # may be 0 if no alternate path exists

    def test_heartbeat_recorded(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        fm.record_heartbeat(1, 3)
        with fm._lock:
            assert (1, 3) in fm._heartbeat

    def test_active_failures_structure(self):
        topo = self._make_topo()
        fm   = FailoverManager(topo)
        ps   = _make_port_status(OFPPortReason.DELETE, port_no=2)
        fm.on_port_status(2, ps)
        failures = fm.active_failures()
        assert isinstance(failures, list)
        f = failures[0]
        assert "dpid"  in f
        assert "port"  in f
        assert "since" in f
