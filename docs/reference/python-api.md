# Python API

privmap is primarily a CLI tool, but the underlying modules are
importable and stable enough to use programmatically, for example by
embedding privmap analysis in a larger orchestration script.

This page documents the public surface. Anything not listed here is
considered internal and may change without notice between minor releases.

## Top-level imports

```python
from privmap import (
    __version__,
    GraphBuilder,
    PrivilegeGraph,
    analyze_paths,
    export_json,
    export_markdown,
    Severity,
)
```

## Building a graph

```python
from privmap import GraphBuilder

builder = GraphBuilder(
    root_path="/",
    scan_paths=["/etc", "/usr"],
    snapshot_mode=False,
)
graph = builder.build()

print(graph.node_count, graph.edge_count)
```

`GraphBuilder` accepts an optional `progress` callback for status updates:

```python
def on_progress(phase: str, detail: str | None) -> None:
    print(f"[{phase}] {detail or ''}")

builder = GraphBuilder(progress=on_progress)
```

For snapshot mode, point `root_path` at an already-extracted snapshot
directory and set `snapshot_mode=True`. The CLI handles archive
extraction; the library does not.

## Analyzing paths

```python
from privmap import analyze_paths, Severity

paths = analyze_paths(
    graph,
    source_users=["www-data"],   # None means all non-privileged users
    max_depth=10,
    min_severity=Severity.HIGH,
)

for path in paths:
    print(path.source.name, "->", path.sink.name, f"({path.hops} hops)")
    print("  severity:", path.severity.value)
    print("  exploitability:", path.exploitability)
    print("  impact:", path.impact)
```

`Severity` is an enum with the standard tiers: `CRITICAL`, `HIGH`,
`MEDIUM`, `LOW`, `INFO`. It supports the usual comparison operators, so
`severity >= Severity.HIGH` works.

## Exporting

```python
from privmap import export_json, export_markdown

print(export_json(paths, graph))
print(export_markdown(paths, graph))
```

Both return strings. For file output, write the string to disk. Neither
function writes directly.

## Inspecting the graph

```python
from privmap import NodeType, EdgeType

# All users
users = graph.get_nodes_by_type(NodeType.USER)

# Edges flowing into a node
edges_in = graph.get_edges_to("user:root")

# Edges flowing out
edges_out = graph.get_edges_from("user:www-data")

# Neighbors (node + connecting edge)
for neighbor, edge in graph.get_neighbors("user:www-data"):
    print(edge.edge_type, "->", neighbor.id)
```

The full node and edge type catalogue is in
[graph model](../concepts/graph-model.md).

## NetworkX interop

```python
nx_graph = graph.to_networkx()       # returns a networkx.MultiDiGraph
```

From there you can export to GraphML, GEXF, dot, or feed it to any
networkx algorithm:

```python
import networkx as nx
nx.write_graphml(nx_graph, "privmap.graphml")
```

This is the recommended path for Gephi, Cytoscape, Neo4j, or any other
graph database or visualizer.

## Stability guarantees

These are stable across patch and minor releases within the 1.x line:

- All identifiers listed in [Top-level imports](#top-level-imports).
- `GraphBuilder.__init__` keyword arguments.
- `analyze_paths` signature and return type.
- `NodeType` and `EdgeType` enum values. New values may be added (v2.0
  added 16 node types and 5 edge types; see [graph model](../concepts/graph-model.md));
  existing values are not removed or renamed within a major version.
- `EscalationPath` attributes used in the examples above.
- The `__version__` string.

These are not stable:

- The internal layout of the `ingestion/` modules.
- `properties` dict keys on nodes and edges. New keys may be added;
  existing keys will not be removed within 1.x but may be deprecated.
- The contents of `AUTH_REQUIRED_SUID`, `KNOWN_SAFE_CAP_BINARIES`,
  `GTFOBINS_SUID`, `SUDO_SHELL_ESCAPE`. These are tuned as needed.
