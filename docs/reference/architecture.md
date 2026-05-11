# Architecture

privmap is organized as five ingesters that all write into a single
shared graph, followed by a traversal pass that reads from it and emits
paths.

```text
                   ┌────────────────────┐
   /etc/passwd  ─> │  IdentityIngester  │ ──┐
   /etc/group      └────────────────────┘   │
   /etc/sudoers                             │
                                            │
                   ┌────────────────────┐   │
   filesystem   ─> │ FilesystemIngester │ ──┤
   walk            └────────────────────┘   │
                                            │
                   ┌────────────────────┐   │     ┌──────────────────┐
   cron, systemd ─>│ ExecutionIngester  │ ──┼──>  │  PrivilegeGraph  │
   init.d          └────────────────────┘   │     └──────────────────┘
                                            │              │
                   ┌────────────────────┐   │              v
   getcap, /proc ─>│CapabilityIngester  │ ──┤    ┌──────────────────────┐
                   └────────────────────┘   │    │  DFS traversal       │
                                            │    │  + validation        │
                   ┌────────────────────┐   │    │  + scoring           │
   /proc         ─>│  ProcessIngester   │ ──┘    └──────────────────────┘
                   └────────────────────┘                  │
                                                           v
                                                  [escalation paths]
```

## Source layout

```text
privmap/
├── cli.py                  # entry point, argparse, snapshot extraction
├── __init__.py             # public API re-exports, __version__
├── ingestion/
│   ├── identity.py         # passwd, group, shadow, sudoers (with aliases)
│   ├── filesystem.py       # perm walk, SUID/SGID, world-writable, ACLs, symlinks
│   ├── execution.py        # cron, systemd units, init.d
│   ├── capabilities.py     # file caps via getcap, process caps via /proc
│   └── processes.py        # running process metadata
├── graph/
│   ├── model.py            # Node, Edge, PrivilegeGraph, EscalationPath
│   ├── builder.py          # coordinates ingesters, emits progress events
│   └── traversal.py        # DFS, validation filters, sink/source predicates
├── analysis/
│   ├── paths.py            # public analyze_paths() (runs traversal + scoring)
│   ├── scoring.py          # exploitability * impact -> severity
│   └── remediation.py      # per-path fix suggestions
└── output/
    ├── cli_output.py       # rich-based terminal renderer
    ├── json_export.py      # structured JSON
    └── markdown_export.py  # GitHub-flavored markdown
```

## Phase ordering

The builder runs ingesters in a fixed order because some emit nodes that
later ingesters reference:

1. **Identity.** Must run first. Creates `USER` and `GROUP` nodes.
   Sudoers parsing emits `SUDO_RULE` nodes and `GRANTS` edges.
2. **Filesystem.** Emits `SUID_BINARY`, `FILE`, `DIRECTORY`,
   world-writable `CAN_WRITE`, and ACL-based `CAN_WRITE` edges. Needs
   `USER` and `GROUP` nodes from phase 1 for group-ACL expansion.
3. **Execution.** Emits `CRON_JOB`, `SYSTEMD_UNIT`, `INITD_SCRIPT` nodes
   and `RUNS_AS` and `EXECUTES` edges. Needs `USER` nodes.
4. **Capabilities.** Emits `FILE`, `CAPABILITY` nodes,
   `HAS_CAPABILITY` edges, and per-user `CAN_EXEC` edges. The CAN_EXEC
   check consults the live filesystem in live mode or the captured
   `permissions.txt` in snapshot mode.
5. **Processes.** Emits `PROCESS` nodes for non-root processes with
   elevated caps. Read-only relative to other phases.

## Live vs snapshot

Every ingester accepts a `snapshot_mode: bool`. When true, it reads from
a captured directory tree (produced by `collect.sh`) instead of running
live queries. The ingesters branch internally on this flag; the graph it
produces is structurally identical.

See
[Snapshot mode: Live vs snapshot](../usage/snapshot-mode.md#live-vs-snapshot)
for the per-ingester difference table.

## Extension points

These are de facto extension points today. A formal plugin API is on the
roadmap.

- **Adding an ingester.** Subclass nothing. Implement
  `ingest(graph: PrivilegeGraph) -> None` and call it from
  `GraphBuilder.build()`. The fixed phase order is enforced manually.
- **Adding a node or edge type.** Extend the `NodeType` and `EdgeType`
  enums in `graph/model.py`. Add scoring rules in `analysis/scoring.py`
  and rendering in each output module.
- **Adding an output format.** Write an `export_<format>(paths, graph)
  -> str` function in `output/`, then wire it into the `--output` choice
  in `cli.py`.
- **Adding to the known-safe lists.** Edit `AUTH_REQUIRED_SUID` in
  `graph/traversal.py` or `KNOWN_SAFE_CAP_BINARIES` in
  `ingestion/capabilities.py`. PRs welcome.

## Performance characteristics

| Phase                | Bottleneck                       | Scaling                                    |
|----------------------|----------------------------------|--------------------------------------------|
| Identity             | `/etc/passwd` parse              | O(users)                                   |
| Filesystem walk      | `os.walk` over scan paths        | O(files in scan paths). Dominant phase.    |
| ACL ingestion        | `getfacl -R` subprocess          | O(files with ACLs). 60s timeout.           |
| Execution            | systemd unit parse               | O(unit files)                              |
| Capabilities         | `getcap -r /` subprocess         | O(capability binaries). 120s timeout.      |
| Processes            | `/proc` enumeration              | O(running processes)                       |
| DFS traversal        | Path explosion in dense graphs   | Bounded by `--max-depth`                   |

On a typical Debian server (~80k files in default scan paths, ~50
users, ~200 SUID binaries, ~300 systemd units), a full run completes
in 30 to 90 seconds. Snapshot mode is faster because subprocess-driven
phases are replaced by file reads.
