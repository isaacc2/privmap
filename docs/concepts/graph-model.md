# Graph model

privmap models a Linux system as a **directed property graph**. Every
permission-relevant entity becomes a node; every relationship between two
entities becomes a directed edge. The graph is the entire data structure
that analysis runs against.

This page is the canonical reference for what nodes and edges mean.

## Nodes

A node represents an entity that can either hold privilege or be used to
gain privilege.

| Node type        | Represents                                                                          |
|------------------|-------------------------------------------------------------------------------------|
| `USER`           | A line in `/etc/passwd`. Uid, primary gid, shell, home, gecos.                      |
| `GROUP`          | A line in `/etc/group`. Gid, member list (handled via edges).                       |
| `SUDO_RULE`      | A single command spec parsed from `/etc/sudoers` or `/etc/sudoers.d/*`.             |
| `FILE`           | A regular file flagged by some ingester (writable, ACL-relevant, executed, etc.).   |
| `DIRECTORY`      | A directory flagged by some ingester (typically world-writable).                    |
| `SUID_BINARY`    | A file with SUID or SGID set.                                                       |
| `CRON_JOB`       | A cron entry (system or user crontab, periodic cron drop-in).                       |
| `SYSTEMD_UNIT`   | A `.service` or `.timer` unit file.                                                 |
| `INITD_SCRIPT`   | An `/etc/init.d` script.                                                            |
| `CAPABILITY`     | A specific Linux capability bound to a specific binary (`cap_setuid` on `/foo`).    |
| `PROCESS`        | A non-root process with elevated effective capabilities.                            |

Each node has:

- `id`. Unique within the graph, deterministic from the source data (for
  example `user:www-data`, `suid:/usr/bin/find`).
- `name`. Display name.
- `properties`. A free-form dict of context (mode bits, ownership,
  exec_commands, etc.). The exact keys depend on the node type and which
  ingester emitted the node.

## Edges

An edge represents a relationship between two nodes that has privilege
significance.

| Edge type        | Source                                       | Target              | Meaning                                              |
|------------------|----------------------------------------------|---------------------|------------------------------------------------------|
| `MEMBER_OF`      | `USER`                                       | `GROUP`             | User belongs to group (primary or supplementary).    |
| `GRANTS`         | `USER` / `GROUP`                             | `SUDO_RULE`         | Principal is authorized by this sudo rule.           |
| `GRANTS`         | `SUDO_RULE`                                  | `USER`              | Sudo rule's effective `runas` user.                  |
| `GRANTS`         | `CAPABILITY`                                 | `USER`              | Holding this cap effectively yields target user.     |
| `CAN_WRITE`      | `USER`                                       | `FILE` / `DIRECTORY`| User can modify the target.                          |
| `CAN_EXEC`       | `USER`                                       | `FILE` / `SUID_BINARY` | User can execute the target.                      |
| `SUID_EXEC`      | `USER`                                       | `SUID_BINARY`       | Any user can invoke this SUID-root binary.           |
| `RUNS_AS`        | `CRON_JOB` / `SYSTEMD_UNIT` / `SUID_BINARY`  | `USER`              | Execution context runs as this user.                 |
| `EXECUTES`       | `CRON_JOB` / `SYSTEMD_UNIT` / `INITD_SCRIPT` | `FILE`              | Execution context invokes this file.                 |
| `HAS_CAPABILITY` | `FILE`                                       | `CAPABILITY`        | File has the named capability set.                   |

Each edge has:

- `source_id`, `target_id`. Node ids on either end.
- `edge_type`. One of the above.
- `properties`. Context about the relationship (mode bits at the time of
  observation, the original command string, ACL entry it came from, etc.).

## Sources and sinks

Traversal is from **source** nodes to **sink** nodes.

A **source** is any node from which an attacker can plausibly start:

- `USER` nodes with `uid != 0` and a real shell (not `/usr/sbin/nologin`,
  `/bin/false`, or similar).

A **sink** is any node that represents successful escalation:

- `USER` node with `uid == 0` (root).
- `SUDO_RULE` with command `ALL` (full sudo).
- `CAPABILITY` with a dangerous cap (`cap_setuid`, `cap_sys_admin`, etc.)
  on a binary that is not on the [known-safe allowlist](#known-safe-binaries).

A path that connects a source to a sink, through valid edge transitions,
is a candidate escalation path. It is then run through
[validation and scoring](path-validation.md) before being reported.

## Known-safe binaries

Some SUID binaries and capability binaries are part of normal system
operation and do not represent escalation paths even though they appear
"dangerous" structurally:

- **Auth-required SUID**. `su`, `sudo`, `pkexec`, `doas`, `passwd`,
  `chsh`, `gpasswd`, `newgrp`, `mount`, `umount`, `ssh-agent`, `login`,
  and similar. These gate access behind a credential prompt and are SUID
  by design.
- **Known-safe capability binaries**. `ping`, `mtr`, `traceroute`,
  `snap-confine`, `chronyd`, `systemd-detect-virt`, and similar. These
  use capabilities internally for a narrow purpose without exposing them
  to the caller.

These lists live in `privmap.graph.traversal` (`AUTH_REQUIRED_SUID`) and
`privmap.ingestion.capabilities` (`KNOWN_SAFE_CAP_BINARIES`). privmap
does not perform version-based CVE matching against these binaries. Use a
vulnerability scanner alongside it if that is in your threat model.

## Graph export

The full graph (every node, every edge, every property) is serializable
to JSON via `--export-graph` or programmatically via `graph.to_dict()`.
The format is stable across patch versions.

```bash
privmap --export-graph graph.json
```

For downstream graph-DB workflows,
`privmap.graph.model.PrivilegeGraph.to_networkx()` returns a
`networkx.MultiDiGraph` instance you can pass to GraphML, Gephi, Neo4j
importers, and similar.
