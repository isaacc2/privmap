"""Rich terminal output renderer."""
from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from privmap.graph.model import EscalationPath, PrivilegeGraph, Severity
from privmap.analysis.paths import group_paths_by_user


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[!]",
    Severity.MEDIUM: "[~]",
    Severity.LOW: "[-]",
    Severity.INFO: "[i]",
}


def render_cli(
    paths: List[EscalationPath],
    graph: PrivilegeGraph,
    console: Console = None,
) -> None:
    """Render escalation paths to the terminal using rich."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        Panel.fit(
            "[bold]privmap[/bold] — Linux Privilege Graph Engine",
            border_style="blue",
        )
    )
    console.print()

    # Summary
    _render_summary(console, paths, graph)
    console.print()

    if not paths:
        console.print("[green]No escalation paths found.[/green]")
        console.print()
        return

    # Group by user and render
    grouped = group_paths_by_user(paths)
    for username, user_paths in grouped.items():
        _render_user_paths(console, username, user_paths)


def _render_summary(
    console: Console,
    paths: List[EscalationPath],
    graph: PrivilegeGraph,
) -> None:
    table = Table(title="Scan Summary", show_header=False, border_style="dim")
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Graph nodes", str(graph.node_count))
    table.add_row("Graph edges", str(graph.edge_count))
    table.add_row("Escalation paths", str(len(paths)))

    severity_counts = {}
    for p in paths:
        sev = p.severity.value if p.severity else "UNKNOWN"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev_name, 0)
        if count > 0:
            sev_enum = Severity(sev_name)
            color = SEVERITY_COLORS.get(sev_enum, "")
            table.add_row(sev_name, f"[{color}]{count}[/{color}]")

    console.print(table)


def _render_user_paths(
    console: Console,
    username: str,
    paths: List[EscalationPath],
) -> None:

    max_sev = max((p.severity for p in paths if p.severity), default=Severity.INFO)
    color = SEVERITY_COLORS.get(max_sev, "")
    icon = SEVERITY_ICONS.get(max_sev, "")

    header = Text()
    header.append(f"{icon} ", style=color)
    header.append(f"{len(paths)} escalation path(s) found for user: ", style=color)
    header.append(username, style=f"{color} underline")

    console.print(Panel(header, border_style=color.replace("bold ", "")))

    for i, path in enumerate(paths, 1):
        _render_path(console, i, path)

    console.print()


def _render_path(console: Console, index: int, path: EscalationPath) -> None:
    sev = path.severity or Severity.INFO
    color = SEVERITY_COLORS.get(sev, "")

    console.print(
        f"  [{color}]{sev.value}[/{color}] Path {index} — "
        f"{path.source.name} → {path.sink.name} "
        f"({path.hop_count} hop{'s' if path.hop_count != 1 else ''})"
    )

    tree = Tree(f"  [bold]{path.source.display_name}[/bold]")
    for j, edge in enumerate(path.edges):
        target_node = path.nodes[j + 1] if j + 1 < len(path.nodes) else None
        edge_label = f"[dim]{edge.edge_type.value:12s}[/dim]"

        if target_node:
            detail = target_node.display_name
            props = []
            if target_node.properties.get("mode"):
                props.append(f"mode: {target_node.properties['mode']}")
            if target_node.properties.get("run_as"):
                props.append(f"runs-as: {target_node.properties['run_as']}")
            if edge.properties.get("nopasswd"):
                props.append("NOPASSWD")
            if edge.properties.get("reason"):
                props.append(edge.properties["reason"])
            if props:
                detail += f"  [dim]({', '.join(props)})[/dim]"
            tree.add(f"{edge_label}  {detail}")
        else:
            tree.add(f"{edge_label}  {edge.target_id}")

    # Sink
    tree.add(f"[bold green]→ {path.sink.display_name}[/bold green]")
    console.print(tree)

    # Risk and remediation
    if path.risk_description:
        console.print(f"    [dim]Risk:[/dim] {path.risk_description}")
    if path.remediation:
        console.print(f"    [dim]Remediation:[/dim] {path.remediation}")

    console.print(
        f"    [dim]Scores: exploitability={path.exploitability_score:.1f}/10, "
        f"impact={path.impact_score:.1f}/10[/dim]"
    )
    console.print()
