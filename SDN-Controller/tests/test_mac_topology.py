import time
import pytest

from sdn.mac_table import MACTable
from sdn.topology import TopologyGraph


class TestMACTable:
    def test_learn_and_lookup(self):
        t = MACTable()
        t.learn(1, "aa:bb:cc:dd:ee:ff", port=3)
        assert t.lookup(1, "aa:bb:cc:dd:ee:ff") == 3

    def test_unknown_mac_returns_none(self):
        t = MACTable()
        assert t.lookup(1, "11:22:33:44:55:66") is None

    def test_learn_returns_true_for_new(self):
        t = MACTable()
        assert t.learn(1, "aa:aa:aa:aa:aa:aa", 2) is True

    def test_learn_returns_false_for_same_port(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        assert t.learn(1, "aa:aa:aa:aa:aa:aa", 2) is False

    def test_learn_returns_true_for_port_change(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        assert t.learn(1, "aa:aa:aa:aa:aa:aa", 5) is True

    def test_port_change_updates_entry(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        t.learn(1, "aa:aa:aa:aa:aa:aa", 5)
        assert t.lookup(1, "aa:aa:aa:aa:aa:aa") == 5

    def test_expire_removes_old_entry(self):
        t = MACTable(idle_timeout=0.05)
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        time.sleep(0.1)
        assert t.lookup(1, "aa:aa:aa:aa:aa:aa") is None

    def test_expire_method_returns_count(self):
        t = MACTable(idle_timeout=0.05)
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        t.learn(1, "bb:bb:bb:bb:bb:bb", 3)
        time.sleep(0.1)
        removed = t.expire()
        assert removed == 2

    def test_per_dpid_isolation(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        assert t.lookup(2, "aa:aa:aa:aa:aa:aa") is None

    def test_clear_dpid(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        t.clear_dpid(1)
        assert t.lookup(1, "aa:aa:aa:aa:aa:aa") is None

    def test_snapshot(self):
        t = MACTable()
        t.learn(1, "aa:aa:aa:aa:aa:aa", 2)
        t.learn(1, "bb:bb:bb:bb:bb:bb", 3)
        snap = t.snapshot(1)
        assert snap["aa:aa:aa:aa:aa:aa"] == 2
        assert snap["bb:bb:bb:bb:bb:bb"] == 3


class TestTopologyGraph:
    def test_add_switch(self):
        g = TopologyGraph()
        g.add_switch(1, ports={1, 2, 3})
        assert 1 in g.all_switches()

    def test_switch_ports(self):
        g = TopologyGraph()
        g.add_switch(1, ports={1, 2, 3})
        assert g.switch_ports(1) == {1, 2, 3}

    def test_add_link_bidirectional(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        g.add_link(1, 3, 2, 4)
        assert g.link_port(1, 2) == (3, 4)
        assert g.link_port(2, 1) == (4, 3)

    def test_neighbours(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        g.add_link(1, 3, 2, 4)
        nb = g.neighbours(1)
        assert (2, 3, 4) in nb

    def test_remove_switch_removes_links(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        g.add_link(1, 1, 2, 1)
        g.remove_switch(1)
        assert 1 not in g.all_switches()
        assert g.link_port(1, 2) is None

    def test_shortest_path_direct(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        g.add_link(1, 1, 2, 1)
        path = g.shortest_path(1, 2)
        assert path == [1, 2]

    def test_shortest_path_multi_hop(self):
        g = TopologyGraph()
        for i in range(1, 5):
            g.add_switch(i)
        g.add_link(1, 1, 2, 1)
        g.add_link(2, 2, 3, 1)
        g.add_link(3, 2, 4, 1)
        path = g.shortest_path(1, 4)
        assert path == [1, 2, 3, 4]

    def test_shortest_path_no_route(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        assert g.shortest_path(1, 2) == []

    def test_shortest_path_same_node(self):
        g = TopologyGraph()
        g.add_switch(1)
        assert g.shortest_path(1, 1) == [1]

    def test_shortest_path_prefers_fewer_hops(self):
        g = TopologyGraph()
        for i in range(1, 6):
            g.add_switch(i)
        # Direct path: 1→5
        g.add_link(1, 1, 5, 1)
        # Long path: 1→2→3→4→5
        g.add_link(1, 2, 2, 1)
        g.add_link(2, 2, 3, 1)
        g.add_link(3, 2, 4, 1)
        g.add_link(4, 2, 5, 2)
        path = g.shortest_path(1, 5)
        assert len(path) == 2   # should take direct path

    def test_spanning_tree_no_loops(self):
        g = TopologyGraph()
        for i in range(1, 4):
            g.add_switch(i)
        # Ring: 1–2–3–1
        g.add_link(1, 1, 2, 1)
        g.add_link(2, 2, 3, 1)
        g.add_link(3, 2, 1, 2)
        st = g.spanning_tree_ports()
        # Count tree edges: spanning tree of 3 nodes has exactly 2 edges
        total_ports = sum(len(p) for p in st.values())
        assert total_ports == 4   # 2 edges × 2 endpoints each

    def test_update_and_query_host(self):
        g = TopologyGraph()
        g.add_switch(1)
        g.update_host("aa:bb:cc:dd:ee:ff", dpid=1, port=5, ip="10.0.0.1")
        loc = g.host_location("aa:bb:cc:dd:ee:ff")
        assert loc is not None
        assert loc.port == 5
        assert loc.ip   == "10.0.0.1"

    def test_is_inter_switch_port(self):
        g = TopologyGraph()
        g.add_switch(1); g.add_switch(2)
        g.add_link(1, 3, 2, 4)
        assert g.is_inter_switch_port(1, 3) is True
        assert g.is_inter_switch_port(1, 1) is False

    def test_to_dict_structure(self):
        g = TopologyGraph()
        g.add_switch(1, ports={1, 2})
        d = g.to_dict()
        assert "switches" in d
        assert "links" in d
        assert "hosts" in d
