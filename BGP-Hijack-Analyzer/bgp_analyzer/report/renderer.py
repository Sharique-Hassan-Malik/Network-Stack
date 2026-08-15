"""
Rich terminal renderer for AnalysisResult.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from bgp_analyzer.analyzer import AnalysisResult

console = Console()

_SEV_COLOR = {
    "high":   "bright_red",
    "medium": "yellow",
    "low":    "bright_cyan",
    "info":   "dim",
}

_KIND_LABEL = {
    "origin_hijack":    "Origin Hijack",
    "subprefix_hijack": "Sub-prefix Hijack",
    "route_leak":       "Route Leak",
    "bogon_prefix":     "Bogon Prefix",
    "bogon_as":         "Bogon AS",
    "path_loop":        "Path Loop",
    "path_anomaly":     "Path Anomaly",
}


def render(result: "AnalysisResult") -> None:
    _render_summary(result)
    if result.alerts:
        _render_alert_table(result)
    else:
        console.print("\n[bold green]No anomalies detected.[/bold green]\n")


def _render_summary(result: "AnalysisResult") -> None:
    sev = result.by_severity
    body = "\n".join([
        f"  Baseline prefixes : [bold]{result.baseline_prefixes:>10,}[/bold]",
        f"  Baseline routes   : [bold]{result.baseline_routes:>10,}[/bold]",
        f"  Current routes    : [bold]{result.current_routes_scanned:>10,}[/bold]",
        f"  Total alerts      : [bold]{len(result.alerts):>10,}[/bold]",
        "",
        f"  [bright_red]High      {len(sev['high']):>6}[/bright_red]",
        f"  [yellow]Medium    {len(sev['medium']):>6}[/yellow]",
        f"  [bright_cyan]Low       {len(sev['low']):>6}[/bright_cyan]",
    ])
    console.print(Panel(body, title="BGP Hijack Analysis Summary", border_style="blue"))

    counts = result.alert_counts
    if not counts:
        return

    tbl = Table(
        title="Alert Breakdown",
        box=box.SIMPLE_HEAD,
        title_style="bold",
        show_header=True,
    )
    tbl.add_column("Type", style="bold")
    tbl.add_column("Count", justify="right")
    for kind, n in sorted(counts.items(), key=lambda x: -x[1]):
        tbl.add_row(_KIND_LABEL.get(kind, kind), str(n))
    console.print(tbl)


def _render_alert_table(result: "AnalysisResult") -> None:
    tbl = Table(
        title=f"Alerts  ({len(result.alerts)} total)",
        box=box.SIMPLE_HEAD,
        show_lines=True,
        title_style="bold",
    )
    tbl.add_column("Sev",          width=8)
    tbl.add_column("Type",         width=20)
    tbl.add_column("Prefix",       width=22)
    tbl.add_column("New Origin",   width=10)
    tbl.add_column("Description",  min_width=45)

    for alert in result.alerts:
        color  = _SEV_COLOR.get(alert.severity, "white")
        origin = (
            str(alert.current_route.origin_as)
            if alert.current_route and alert.current_route.origin_as is not None
            else "—"
        )
        tbl.add_row(
            f"[{color}]{alert.severity.upper()}[/{color}]",
            _KIND_LABEL.get(alert.kind, alert.kind),
            str(alert.prefix),
            origin,
            alert.description,
        )

    console.print(tbl)
