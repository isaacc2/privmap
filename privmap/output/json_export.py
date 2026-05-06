"""Export analysis results as structured JSON."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from privmap.graph.model import EscalationPath, PrivilegeGraph


def export_json(
    paths: List[EscalationPath],
    graph: PrivilegeGraph,
    include_graph: bool = False,
) -> str:
    """Export paths (and optionally the full graph) as JSON."""
    output: Dict[str, Any] = {
        "version": "1.0.0",
        "summary": {
            "total_paths": len(paths),
            "severity_counts": _severity_counts(paths),
            "graph_nodes": graph.node_count,
            "graph_edges": graph.edge_count,
        },
        "paths": [p.to_dict() for p in paths],
    }

    if include_graph:
        output["graph"] = graph.to_dict()

    return json.dumps(output, indent=2, default=str)


def _severity_counts(paths: List[EscalationPath]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in paths:
        sev = p.severity.value if p.severity else "UNKNOWN"
        counts[sev] = counts.get(sev, 0) + 1
    return counts
