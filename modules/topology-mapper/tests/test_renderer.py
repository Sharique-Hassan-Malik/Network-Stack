import json
import tempfile
from pathlib import Path

from ntm.renderer import render_html
from ntm.topology import NetworkGraph
from ntm.fingerprint import OSGuess


def _simple_graph() -> NetworkGraph:
    g = NetworkGraph()
    g.add_node("192.168.1.1", is_gateway=True, is_router=True)
    g.add_node("192.168.1.10")
    g.add_node("192.168.1.20")
    g.add_edge("192.168.1.1",  "192.168.1.10", rtt_ms=0.5)
    g.add_edge("192.168.1.1",  "192.168.1.20", rtt_ms=1.2)
    return g


class TestRenderHTML:
    def test_creates_file(self, tmp_path):
        g = _simple_graph()
        out = render_html(g, "192.168.1.100", output=tmp_path / "out.html")
        assert out.exists()
        assert out.stat().st_size > 0

    def test_valid_html(self, tmp_path):
        g = _simple_graph()
        out = render_html(g, "192.168.1.100", output=tmp_path / "out.html")
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "<script" in content

    def test_graph_json_embedded(self, tmp_path):
        g = _simple_graph()
        out = render_html(g, "192.168.1.100", output=tmp_path / "out.html")
        content = out.read_text()
        assert "192.168.1.1" in content
        assert "192.168.1.10" in content

    def test_os_guess_embedded(self, tmp_path):
        g = _simple_graph()
        os_guesses = {"192.168.1.10": OSGuess("Linux", "5.x", 80)}
        out = render_html(g, "192.168.1.100", os_guesses=os_guesses, output=tmp_path / "out.html")
        content = out.read_text()
        assert "Linux" in content

    def test_port_map_embedded(self, tmp_path):
        g = _simple_graph()
        port_map = {"192.168.1.10": [22, 80, 443]}
        out = render_html(g, "192.168.1.100", port_map=port_map, output=tmp_path / "out.html")
        content = out.read_text()
        assert "443" in content

    def test_empty_graph(self, tmp_path):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        out = render_html(g, "10.0.0.1", output=tmp_path / "out.html")
        assert out.exists()

    def test_rtt_rounded(self, tmp_path):
        g = NetworkGraph()
        g.add_node("10.0.0.1")
        g.add_node("10.0.0.2")
        g.add_edge("10.0.0.1", "10.0.0.2", rtt_ms=1.23456789)
        out = render_html(g, "10.0.0.1", output=tmp_path / "out.html")
        content = out.read_text()
        assert "1.235" in content
