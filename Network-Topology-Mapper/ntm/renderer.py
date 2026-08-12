"""
Render the NetworkGraph as a self-contained interactive HTML file.

The HTML embeds a D3 v7 force-directed graph where:
  - Circles represent hosts (blue = regular, orange = gateway/router)
  - Lines represent observed hop relationships, labeled with RTT
  - Hovering a node shows IP, hostname and OS guess
  - Clicking a node pins/unpins it

The D3 bundle is loaded from a CDN.  The graph data is embedded directly
as JSON in the HTML file so the output is a single portable file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .topology import NetworkGraph


_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Network Topology Map</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f1117; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; overflow: hidden; }

    #canvas { width: 100vw; height: 100vh; }

    .link { stroke: #3a4a5a; stroke-opacity: 0.7; stroke-width: 1.5px; }
    .link-label { font-size: 10px; fill: #6b7a8a; pointer-events: none; }

    .node circle { stroke-width: 2px; cursor: pointer; }
    .node circle.host    { fill: #1e3a5f; stroke: #4a90d9; }
    .node circle.router  { fill: #4a2000; stroke: #e87c00; }
    .node circle.gateway { fill: #1a3a1a; stroke: #4caf50; }
    .node circle.local   { fill: #2a1a4a; stroke: #9c64e0; }

    .node text { font-size: 11px; fill: #b0c0d0; pointer-events: none; }

    #tooltip {
      position: absolute; display: none;
      background: rgba(15,17,23,0.95); border: 1px solid #3a4a5a;
      border-radius: 6px; padding: 10px 14px; font-size: 12px;
      line-height: 1.6; max-width: 260px; pointer-events: none;
    }
    #tooltip .label { color: #9c64e0; font-weight: 600; }
    #tooltip .val   { color: #e0e0e0; }

    #legend {
      position: absolute; bottom: 20px; left: 20px;
      background: rgba(15,17,23,0.85); border: 1px solid #3a4a5a;
      border-radius: 6px; padding: 12px 16px; font-size: 12px;
    }
    .legend-item { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
    .legend-dot  { width: 12px; height: 12px; border-radius: 50%; border: 2px solid; flex-shrink: 0; }

    #info { position: absolute; top: 16px; left: 16px; font-size: 13px; opacity: 0.7; }
  </style>
</head>
<body>
<svg id="canvas"></svg>
<div id="tooltip"></div>
<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#2a1a4a;border-color:#9c64e0"></div> Local machine</div>
  <div class="legend-item"><div class="legend-dot" style="background:#1a3a1a;border-color:#4caf50"></div> Gateway / router</div>
  <div class="legend-item"><div class="legend-dot" style="background:#4a2000;border-color:#e87c00"></div> Router (intermediate)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#1e3a5f;border-color:#4a90d9"></div> Host</div>
</div>
<div id="info">Drag to move &middot; Scroll to zoom &middot; Click to pin</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const GRAPH = __GRAPH_JSON__;

const width  = window.innerWidth;
const height = window.innerHeight;

const svg = d3.select("#canvas")
  .attr("width",  width)
  .attr("height", height);

const g = svg.append("g");

svg.call(d3.zoom().scaleExtent([0.2, 4]).on("zoom", e => g.attr("transform", e.transform)));

// Build lookup
const nodeById = Object.fromEntries(GRAPH.nodes.map(n => [n.ip, n]));

const sim = d3.forceSimulation(GRAPH.nodes)
  .force("link", d3.forceLink(GRAPH.edges).id(d => d.ip).distance(120))
  .force("charge", d3.forceManyBody().strength(-400))
  .force("center", d3.forceCenter(width / 2, height / 2))
  .force("collision", d3.forceCollide(40));

const link = g.append("g").selectAll("line")
  .data(GRAPH.edges).join("line").attr("class", "link");

const linkLabel = g.append("g").selectAll("text")
  .data(GRAPH.edges.filter(e => e.rtt_ms > 0)).join("text")
  .attr("class", "link-label")
  .text(d => d.rtt_ms.toFixed(1) + " ms");

const node = g.append("g").selectAll("g")
  .data(GRAPH.nodes).join("g")
  .attr("class", "node")
  .call(d3.drag()
    .on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on("drag",  (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on("end",   (e, d) => {
      if (!e.active) sim.alphaTarget(0);
      if (!d._pinned) { d.fx = null; d.fy = null; }
    })
  )
  .on("click", (e, d) => {
    d._pinned = !d._pinned;
    if (!d._pinned) { d.fx = null; d.fy = null; }
  });

node.append("circle")
  .attr("r", d => d.is_gateway ? 18 : (d.is_router ? 14 : 11))
  .attr("class", d => d.is_local ? "local" : d.is_gateway ? "gateway" : d.is_router ? "router" : "host");

node.append("text")
  .attr("dy", d => (d.is_gateway ? 18 : 14) + 14)
  .attr("text-anchor", "middle")
  .text(d => d.hostname ? d.hostname.split(".")[0] : d.ip);

const tooltip = document.getElementById("tooltip");

node
  .on("mouseover", (e, d) => {
    const lines = [
      `<span class="label">IP</span> <span class="val">${d.ip}</span>`,
      d.hostname ? `<span class="label">Host</span> <span class="val">${d.hostname}</span>` : "",
      d.is_gateway ? `<span class="label">Role</span> <span class="val">Gateway</span>` :
        d.is_router ? `<span class="label">Role</span> <span class="val">Router</span>` :
        `<span class="label">Role</span> <span class="val">Host</span>`,
      d.os_family ? `<span class="label">OS</span> <span class="val">${d.os_family}${d.os_version ? " " + d.os_version : ""} (${d.os_confidence}%)</span>` : "",
      d.open_ports && d.open_ports.length ? `<span class="label">Open ports</span> <span class="val">${d.open_ports.join(", ")}</span>` : "",
    ].filter(Boolean).join("<br>");
    tooltip.innerHTML = lines;
    tooltip.style.display = "block";
  })
  .on("mousemove", e => {
    tooltip.style.left = (e.pageX + 14) + "px";
    tooltip.style.top  = (e.pageY - 20) + "px";
  })
  .on("mouseout", () => { tooltip.style.display = "none"; });

sim.on("tick", () => {
  link
    .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
  linkLabel
    .attr("x", d => (d.source.x + d.target.x) / 2)
    .attr("y", d => (d.source.y + d.target.y) / 2);
  node.attr("transform", d => `translate(${d.x},${d.y})`);
});
</script>
</body>
</html>
"""


def render_html(
    graph: NetworkGraph,
    local_ip: str,
    os_guesses: dict | None = None,
    port_map: dict | None = None,
    output: Path | str = "topology.html",
) -> Path:
    """
    Write a self-contained interactive HTML file visualising graph.

    Parameters
    ----------
    graph : NetworkGraph
    local_ip : str
        The scanning machine's IP (marked distinctly).
    os_guesses : dict, optional
        Mapping ip → OSGuess objects.
    port_map : dict, optional
        Mapping ip → list[int] of open ports.
    output : Path or str
        Destination file path.
    """
    nodes = []
    for ip, node in graph.nodes.items():
        entry: dict = {
            "ip":         ip,
            "is_gateway": node.is_gateway,
            "is_router":  node.is_router,
            "is_local":   ip == local_ip,
            "hostname":   node.hostname,
        }
        if os_guesses and ip in os_guesses:
            g = os_guesses[ip]
            entry["os_family"]     = g.family
            entry["os_version"]    = g.version
            entry["os_confidence"] = g.confidence
        if port_map and ip in port_map:
            entry["open_ports"] = sorted(port_map[ip])
        nodes.append(entry)

    edges = [
        {"src": e.src, "dst": e.dst, "rtt_ms": round(e.rtt_ms, 3), "source": e.src, "target": e.dst}
        for e in graph.edges
    ]

    graph_json = json.dumps({"nodes": nodes, "edges": edges})
    html = _TEMPLATE.replace("__GRAPH_JSON__", graph_json)

    output_path = Path(output)
    output_path.write_text(html, encoding="utf-8")
    return output_path
