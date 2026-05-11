# Output formats

privmap supports three output formats, selected with `--output` or `-o`:

| Format     | Stream | Best for                                          |
|------------|--------|---------------------------------------------------|
| `cli`      | stdout | Interactive terminal use (default).               |
| `json`     | stdout | SIEM ingestion, scripting, diffing.               |
| `markdown` | stdout | Embedding in tickets, PRs, incident reports.      |

Stderr is always available for the progress spinner and log lines,
regardless of the chosen output format. That separation lets you safely
redirect:

```bash
privmap --output json > report.json   # spinner still visible on stderr
```

## `cli`: rich terminal

The default. Uses [`rich`](https://rich.readthedocs.io) for color, boxes,
tables, and tree-style path layout. Autodetects the terminal width and
respects `NO_COLOR`.

```text
[CRITICAL] 1 escalation path found for user: anypuppet

Path 1: anypuppet -> sudo -> ALL (2 hops)
  user:anypuppet
├── MEMBER_OF     group:sudo
├── GRANTS        sudo_rule:sudo -> ALL
└── -> sudo_rule:sudo -> ALL
    Risk: Membership in admin group 'sudo' grants full root via sudo
    Remediation: If anypuppet is not an admin account, remove from sudo group
    Scores: exploitability=9.5/10, impact=10.0/10
```

## `json`: structured data

Schema (informal):

```json
{
  "version": "1.0.5",
  "summary": {
    "total_paths": 3,
    "severity_counts": {"CRITICAL": 1, "HIGH": 2},
    "graph_nodes": 2538,
    "graph_edges": 86909
  },
  "paths": [
    {
      "source": {"id": "user:www-data", "name": "www-data", "type": "USER"},
      "sink":   {"id": "user:root",     "name": "root",     "type": "USER"},
      "severity": "CRITICAL",
      "exploitability": 9.0,
      "impact": 10.0,
      "hops": 3,
      "nodes": [ ... ],
      "edges": [ ... ],
      "risk": "...",
      "remediation": "..."
    }
  ]
}
```

### Stable fields

These fields are part of the documented contract and will not change
without a major-version bump:

- `version`. The privmap version that produced the report.
- `summary.total_paths`
- `summary.severity_counts`
- `paths[].source.id`, `paths[].sink.id`
- `paths[].severity`
- `paths[].exploitability`, `paths[].impact`
- `paths[].nodes[].id`, `paths[].nodes[].type`
- `paths[].edges[].source_id`, `paths[].edges[].target_id`,
  `paths[].edges[].edge_type`

### Property bags

`nodes[].properties` and `edges[].properties` are best-effort context.
New keys may be added between minor versions; existing keys are not
removed. Consume them defensively.

### Including the full graph

```bash
privmap --export-graph graph.json --output json > paths.json
```

`--export-graph` dumps every node and edge to a separate file.
`--output json` reports only the escalation paths. Use both if you want
downstream tooling to do its own queries.

## `markdown`: human-readable report

GitHub-flavored markdown with headings per source user, tables for graph
statistics, and indented code blocks for path traces. Useful for pasting
into issue trackers or pull requests.

```bash
privmap --output markdown > report.md
```

Renders cleanly in GitHub, GitLab, and most static-site generators.

## A note on stability

The `cli` format is meant for humans; its exact layout (column widths,
color choices, tree characters) may change between minor releases. Do not
regex the CLI output in automation. Use `--output json` for that.
