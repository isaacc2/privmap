"""Export analysis results as Markdown report."""
from __future__ import annotations

from typing import List

from privmap.graph.model import EscalationPath, PrivilegeGraph
from privmap.analysis.paths import group_paths_by_user


def export_markdown(
    paths: List[EscalationPath],
    graph: PrivilegeGraph,
) -> str:
    """Generate a Markdown report of escalation paths."""
    lines = []
    lines.append("# privmap — Privilege Escalation Report\n")

    # Summary
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Graph nodes | {graph.node_count} |")
    lines.append(f"| Graph edges | {graph.edge_count} |")
    lines.append(f"| Total escalation paths | {len(paths)} |")

    severity_counts = {}
    for p in paths:
        sev = p.severity.value if p.severity else "UNKNOWN"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_name in severity_counts:
            lines.append(f"| {sev_name} | {severity_counts[sev_name]} |")

    lines.append("")

    if not paths:
        lines.append("**No escalation paths found.**\n")
        return "\n".join(lines)

    # Paths grouped by user
    grouped = group_paths_by_user(paths)

    for username, user_paths in grouped.items():
        lines.append(f"## User: `{username}`\n")
        lines.append(f"{len(user_paths)} escalation path(s) found.\n")

        for i, path in enumerate(user_paths, 1):
            sev = path.severity.value if path.severity else "UNKNOWN"
            lines.append(
                f"### Path {i} — `{path.source.name}` → `{path.sink.name}` "
                f"({path.hop_count} hops) [{sev}]\n"
            )

            lines.append("```")
            lines.append(f"  {path.source.display_name}")
            for j, edge in enumerate(path.edges):
                target = path.nodes[j + 1] if j + 1 < len(path.nodes) else None
                target_str = target.display_name if target else edge.target_id
                props = []
                if target and target.properties.get("mode"):
                    props.append(f"mode: {target.properties['mode']}")
                if edge.properties.get("nopasswd"):
                    props.append("NOPASSWD")
                prop_str = f"  ({', '.join(props)})" if props else ""
                lines.append(f"    {edge.edge_type.value:12s}  {target_str}{prop_str}")
            lines.append(f"  → {path.sink.display_name}")
            lines.append("```\n")

            lines.append(f"**Risk:** {path.risk_description}\n")
            lines.append(f"**Remediation:** {path.remediation}\n")
            lines.append(
                f"**Scores:** exploitability={path.exploitability_score:.1f}/10, "
                f"impact={path.impact_score:.1f}/10\n"
            )

    # Remediation checklist
    lines.append("## Remediation Checklist\n")
    lines.append("| # | Severity | Path | Action |")
    lines.append("|---|----------|------|--------|")

    for i, path in enumerate(paths, 1):
        sev = path.severity.value if path.severity else "-"
        chain = f"`{path.source.name}` → `{path.sink.name}`"
        remedy = path.remediation.replace("|", "\\|")
        lines.append(f"| {i} | {sev} | {chain} | {remedy} |")

    lines.append("")
    return "\n".join(lines)
