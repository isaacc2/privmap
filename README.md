# privmap

**Linux privilege graph engine** — Model effective access. Trace escalation paths. Understand your attack surface.

privmap ingests system configuration data, constructs a directed graph of privilege relationships, and performs reachability analysis to surface concrete escalation paths.

```
[CRITICAL] 2 escalation paths found for user: www-data

Path 1 — www-data → root (4 hops)
  www-data
    MEMBER_OF  group: adm
    CAN_WRITE  file: /etc/logrotate.d/nginx  (mode: 0664)
    EXECUTES   cron: /etc/cron.daily  (runs-as: root)
  → root

  Risk: Writable logrotate config executed by root daily cron
  Remediation: chmod 644 /etc/logrotate.d/nginx; chown root:root /etc/logrotate.d/nginx
```

## Installation

```bash
# Clone the repository
git clone https://github.com/youruser/privmap.git
cd privmap

# Install in editable mode (recommended for development)
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

## Quick start

### Live system analysis (requires root for full results)

```bash
# Full analysis — all users, all paths
sudo privmap

# Analyse specific user(s)
sudo privmap --user www-data --user deploy

# Only show CRITICAL and HIGH severity paths
sudo privmap --min-severity high

# JSON output for SIEM ingestion
sudo privmap --output json > report.json

# Markdown report
sudo privmap --output markdown > report.md

# CI/CD gate — exit non-zero if any CRITICAL paths exist
sudo privmap --exit-code --min-severity critical
```

### Snapshot mode (offline / forensic analysis)

On the target system, run the collector:

```bash
# Copy collect.sh to the target, run as root
chmod +x collect.sh
sudo ./collect.sh
# Produces: privmap_snapshot_<hostname>_<date>.tar.gz
```

Transfer the snapshot to your analysis workstation:

```bash
privmap --snapshot ./privmap_snapshot_target_20250101.tar.gz
```

### Additional options

```bash
# Custom filesystem scan paths
privmap --scan-paths /etc,/usr,/opt,/tmp,/var

# Set max traversal depth (default: 10)
privmap --max-depth 8

# Include INFO-level findings
privmap --min-severity info

# Export full graph as JSON (nodes + edges, not just paths)
privmap --export-graph graph.json

# Verbose logging
privmap -v
privmap -vv  # debug level
```

## How it works

1. **Ingestion** — Reads system configuration (users, groups, sudo rules, file permissions, cron jobs, systemd units, capabilities, running processes)
2. **Graph construction** — Every finding becomes a node or edge in a directed property graph
3. **Reachability analysis** — DFS traversal from each non-root principal toward high-value sinks (root, sudo ALL, dangerous capabilities)
4. **Semantic filtering** — Eliminates false paths (e.g., writable files that nothing executes)
5. **Scoring** — Each path scored on exploitability and impact, assigned severity
6. **Output** — CLI table, JSON, or Markdown with per-path remediation

## Architecture

```
privmap/
├── ingestion/
│   ├── identity.py       # passwd, shadow, group, sudo
│   ├── filesystem.py     # permission walk, SUID, ACL
│   ├── processes.py      # /proc, running services
│   ├── execution.py      # cron, systemd, init.d
│   └── capabilities.py   # linux caps, namespaces
├── graph/
│   ├── model.py          # node/edge types, graph construction
│   ├── builder.py        # wires ingestion output into graph
│   └── traversal.py      # DFS reachability, sink detection
├── analysis/
│   ├── paths.py          # path extraction and deduplication
│   ├── scoring.py        # exploitability + impact scoring
│   └── remediation.py    # per-path fix suggestions
├── output/
│   ├── cli_output.py     # rich terminal renderer
│   ├── json_export.py    # structured JSON export
│   └── markdown_export.py
└── cli.py                # entry point, argument parsing
```

## Dependencies

- Python 3.8+
- [networkx](https://networkx.org/) — graph data structure and algorithms
- [rich](https://github.com/Textualize/rich) — terminal formatting

## Known limitations

- **Sudoers parsing**: Argument-restricted sudo rules (e.g., `sudo /usr/bin/systemctl restart nginx`) reduce exploitability scoring but are not fully validated. Some restricted rules may still be flagged.
- **Capability binaries**: An allowlist suppresses known-safe binaries (snap-confine, ping, mtr, chronyd, etc.). Capability binaries from third-party packages are not on this list and may produce false positives - review the binary's actual exposure before treating as critical.
- **Snapshot mode**: Filesystem permission checks for capability binaries fall back to conservative behavior (assume executable). Live mode is more accurate.
- **Cron command parsing**: The executable extractor uses regex matching on absolute paths, which can match path-like strings inside arguments or comments. Verify findings before acting.
- **No CVE matching**: privmap is a structural analysis tool. It does not check binary versions against known CVEs — use a vulnerability scanner alongside it.

## Contributing

Issues and pull requests welcome. Run tests with `pytest tests/ -v` before submitting.

## License

MIT
