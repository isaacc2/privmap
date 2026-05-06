"""Path extraction, deduplication, and filtering."""
from __future__ import annotations

from typing import List, Optional

from privmap.graph.model import EscalationPath, PrivilegeGraph, Severity
from privmap.graph.traversal import find_escalation_paths
from privmap.analysis.scoring import score_path
from privmap.analysis.remediation import generate_remediation


def analyze_paths(
    graph: PrivilegeGraph,
    source_users: Optional[List[str]] = None,
    max_depth: int = 10,
    min_severity: Severity = Severity.INFO,
) -> List[EscalationPath]:
    """Full path analysis pipeline: find, score, remediate, filter, sort."""
    # Find raw paths
    raw_paths = find_escalation_paths(graph, source_users, max_depth)

    # Score each path
    for path in raw_paths:
        score_path(path)

    # Generate remediation advice
    for path in raw_paths:
        generate_remediation(path)

    # Filter by minimum severity
    filtered = [p for p in raw_paths if p.severity and p.severity >= min_severity]

    # Sort: CRITICAL first, then by hop count (shorter = more exploitable)
    filtered.sort(
        key=lambda p: (-p.severity.rank if p.severity else 0, p.hop_count)
    )

    return filtered


def group_paths_by_user(
    paths: List[EscalationPath],
) -> dict:
    """Group escalation paths by source user."""
    groups = {}
    for path in paths:
        user = path.source.name
        groups.setdefault(user, []).append(path)
    return groups
