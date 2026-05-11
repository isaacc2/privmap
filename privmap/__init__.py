"""privmap — Linux privilege graph engine.

Public Python API. All names re-exported below are stable across patch
and minor releases within the 1.x line. See
https://privmap.readthedocs.io/en/latest/reference/python-api/ for usage.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("privmap")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

from privmap.analysis.paths import analyze_paths
from privmap.graph.builder import GraphBuilder
from privmap.graph.model import (
    Edge,
    EdgeType,
    EscalationPath,
    Node,
    NodeType,
    PrivilegeGraph,
    Severity,
)
from privmap.output.json_export import export_json
from privmap.output.markdown_export import export_markdown

__all__ = [
    "__version__",
    "GraphBuilder",
    "PrivilegeGraph",
    "Node",
    "NodeType",
    "Edge",
    "EdgeType",
    "EscalationPath",
    "Severity",
    "analyze_paths",
    "export_json",
    "export_markdown",
]
