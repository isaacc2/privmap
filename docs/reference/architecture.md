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
│   ├── filesystem.py       # perm walk, SUID/SGID, world/group-writable, ACLs, symlinks
│   ├── execution.py        # cron, systemd units, init.d, config-arg INFLUENCES_EXEC
│   ├── capabilities.py     # file caps via getcap, process caps via /proc
│   ├── processes.py        # running process metadata
│   ├── boot.py             # /etc/profile.d, ld.so.preload/conf, polkit rules, /etc/skel
│   ├── auth.py             # doas, sudo version, sudoers permissions, sudo tokens, Kerberos
│   ├── ssh.py              # sshd_config, host keys, per-user authorized_keys / id_*
│   ├── network.py          # NFS exports, fstab, hosts.equiv, /etc/hosts, /proc/net/*
│   ├── container.py        # Docker/LXC/k8s markers, writable bind mounts, full caps
│   ├── secrets.py          # /proc/[pid]/environ credential scan
│   ├── path_abuse.py       # writable PATH dirs, .sh on PATH, unqualified-binary chains
│   ├── pam.py              # PAM bypass (rootok/permit/nullok/wheel)
│   ├── dbus.py             # /etc/dbus-1/system.d/*.conf policy analysis
│   ├── inetd.py            # /etc/inetd.conf, /etc/xinetd.d/*
│   └── apparmor.py         # /etc/apparmor.d/* profile mode
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
2. **Filesystem.** Emits `SUID_BINARY`, `FILE`, `DIRECTORY`, world-
   and group-writable `CAN_WRITE`, and ACL-based `CAN_WRITE` edges.
   Needs `USER` and `GROUP` nodes from phase 1 for group-member
   expansion.
3. **Execution.** Emits `CRON_JOB`, `SYSTEMD_UNIT`, `INITD_SCRIPT`
   nodes and `RUNS_AS`, `EXECUTES`, and config-arg `INFLUENCES_EXEC`
   edges. Periodic cron scripts have their contents parsed for
   embedded binary invocations and config arguments.
4. **Capabilities.** Emits `FILE`, `CAPABILITY` nodes,
   `HAS_CAPABILITY` edges, and per-user `CAN_EXEC` edges. The CAN_EXEC
   check consults the live filesystem in live mode or the captured
   `permissions.txt` in snapshot mode.
5. **Processes.** Emits `PROCESS` nodes for non-root processes with
   elevated caps. Read-only relative to other phases.
6. **Boot / login.** `PROFILE_SCRIPT`, `LDPRELOAD_FILE`, `POLKIT_RULE`,
   `LOGIN_HOOK` nodes with `EXECUTED_AT_LOGIN` and `INFLUENCES_EXEC`
   edges to root.
7. **Auth.** `DOAS_RULE` nodes, sudo version capture, sudoers file-
   permission rechecks, Kerberos ticket files, active sudo timestamp
   tokens annotated on user nodes.
8. **PAM.** `PAM_FILE` nodes for `/etc/pam.d/*` with findings for
   pam_rootok, pam_permit, nullok, pam_wheel issues.
9. **SSH.** `SSH_KEY` nodes for host and per-user keys, sshd_config
   risky-setting detection.
10. **Network.** `NFS_EXPORT`, `NETWORK_LISTENER` nodes, fstab and
    hosts.equiv parse, /etc/hosts writability.
11. **Container.** `CONTAINER_MARKER` and `MOUNT` nodes for container
    detection and writable bind-mount detection.
12. **PATH abuse.** `PATH_DIR` nodes for every directory on $PATH,
    plus chain wiring from PATH dirs to crons / systemd units that
    invoke unqualified binary names.
13. **Secrets.** `SECRET_FINDING` nodes for credentials surfaced via
    /proc/[pid]/environ.
14. **D-Bus.** `DBUS_POLICY` nodes for over-permissive policy files.
15. **Inetd / xinetd.** `INETD_SERVICE` nodes for legacy super-server
    configuration.
16. **AppArmor.** `APPARMOR_PROFILE` nodes with profile-mode detection.

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
