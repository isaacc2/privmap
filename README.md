# privmap
![tests](https://github.com/isaacc2/privmap/workflows/tests/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Linux privilege graph engine. privmap models effective access on a Linux system as a directed graph and traces concrete privilege escalation paths through it.

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

## Why

Tools like LinPEAS, LinEnum, and BeRoot enumerate privilege-relevant findings as flat lists of independent observations. They report that a file is world-writable, and separately that the same file is executed by a root cron job, but they do not connect those facts into a single exploitable path. The analyst correlates the findings manually.

privmap treats this as a graph reachability problem. Every finding is a node or edge in a directed property graph. The question is not "what misconfigurations exist" but "given this user, what is reachable from here, and through what sequence of relationships."

## Installation

```bash
pip install privmap
```

Or from source:

```bash
git clone https://github.com/isaacc2/privmap.git
cd privmap
pip install -e .
```

Requires Python 3.8 or later.

## Usage

### Live analysis

```bash
sudo privmap                              # full scan, all users
sudo privmap --user www-data --user bob   # specific users
sudo privmap --min-severity high          # filter by severity
sudo privmap --output json > report.json  # JSON for SIEM
sudo privmap --output markdown > report.md
```

Run as root for complete results. Without root, privmap cannot read `/etc/shadow`, walk all of `/etc`, or enumerate other users' processes, and findings will be incomplete.

### Snapshot mode

For offline or forensic analysis, run the collector on the target:

```bash
sudo ./collect.sh
```

This produces `privmap_snapshot_<hostname>_<date>.tar.gz`. Transfer the archive to your analysis workstation and run:

```bash
privmap --snapshot ./privmap_snapshot_target_20250101.tar.gz
```

The collector is POSIX-compliant and has no runtime dependencies.

### CI/CD integration

```bash
privmap --exit-code --min-severity critical
```

Returns non-zero if any path at or above the specified severity is found.

### Other options

```bash
--scan-paths /etc,/usr,/opt    # custom filesystem scan paths
--max-depth 8                   # max traversal depth (default 10)
--export-graph graph.json       # dump full graph as JSON
-v / -vv                        # verbose / debug logging
```

## How it works

1. **Ingestion.** Reads system configuration: users, groups, sudo rules, file permissions, cron jobs, systemd units, capabilities, running processes.
2. **Graph construction.** Each finding becomes a node or edge in a directed property graph.
3. **Reachability analysis.** DFS traversal from each non-privileged principal toward high-value sinks (root, sudo ALL, dangerous capabilities).
4. **Semantic filtering.** Eliminates structurally invalid paths, for example a writable file that no privileged process executes.
5. **Scoring.** Each path is scored on exploitability and impact, then assigned a severity rating.
6. **Output.** CLI, JSON, or Markdown with per-path remediation.

## Architecture

```
privmap/
├── ingestion/
│   ├── identity.py       # passwd, shadow, group, sudo
│   ├── filesystem.py     # permission walk, SUID, ACL
│   ├── processes.py      # /proc, running services
│   ├── execution.py      # cron, systemd, init.d
│   └── capabilities.py   # linux capabilities, namespaces
├── graph/
│   ├── model.py          # node and edge types
│   ├── builder.py        # ingestion coordinator
│   └── traversal.py      # DFS reachability
├── analysis/
│   ├── paths.py          # extraction and deduplication
│   ├── scoring.py        # exploitability and impact
│   └── remediation.py    # per-path fix suggestions
├── output/
│   ├── cli_output.py     # rich terminal renderer
│   ├── json_export.py
│   └── markdown_export.py
└── cli.py                # entry point
```

## Scope

privmap analyses local Linux privilege relationships. It does not perform network enumeration, run exploits, cover Windows or macOS, or replace a CVE-based vulnerability scanner. It is a structural analysis tool.

## Known limitations

* **Argument-restricted sudo rules** receive a reduced exploitability score but are not fully validated. Rules like `sudo /usr/bin/systemctl restart nginx` may still surface as findings.
* **Capability binaries from third-party packages** are not on the known-safe allowlist and may produce false positives. The allowlist covers standard system binaries (snap-confine, ping, mtr, chronyd, and similar).
* **Snapshot mode** falls back to conservative behavior for filesystem permission checks on capability binaries. Live mode is more accurate.
* **Cron command parsing** uses regex matching on absolute paths, which can match path-like strings inside arguments or comments.
* **No CVE matching.** privmap does not check binary versions against known vulnerabilities. Use a vulnerability scanner alongside it.

## Use cases

* **System hardening.** Validate least-privilege configurations and catch unintended escalation paths after changes.
* **Penetration testing.** Replace manual enumeration with deterministic path mapping.
* **Incident response.** Reconstruct how an attacker may have escalated privileges on a compromised host.
* **Education and CTF.** Visualise permission chains that are difficult to reason about manually.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check privmap/
```

## Contributing

Issues and pull requests are welcome. Run the test suite before submitting a PR. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
