<p align="left">
  <img src="assets/logo.png" alt="privmap" width="220">
</p>

# privmap

**Find Linux privilege escalation paths by modeling permissions as a graph.**

privmap reads system configuration (users, groups, sudo and doas rules,
file permissions including group-writable, cron jobs, systemd units,
init.d scripts, inetd and xinetd services, capabilities, running processes,
login scripts, dynamic linker control files, polkit and PAM stacks, SSH
keys and configuration, NFS exports and fstab options, host-trust files,
listening ports, container markers and writable bind mounts, $PATH
directories, AppArmor profiles, D-Bus policies) and builds a directed
property graph. It then runs reachability analysis from each
non-privileged principal toward high-value sinks such as root, dangerous
capabilities, sudo `ALL` rules, doas root rules, and container breakout
markers. The report lists the actual sequence of relationships that lets
a user reach a sink.

```text
[CRITICAL] 2 escalation paths found for user: www-data

Path 1: www-data -> root (4 hops)
  www-data
    MEMBER_OF  group: adm
    CAN_WRITE  file: /etc/logrotate.d/nginx  (mode: 0664)
    EXECUTES   cron: /etc/cron.daily  (runs-as: root)
  -> root

  Risk: Writable logrotate config executed by root daily cron
  Remediation: chmod 644 /etc/logrotate.d/nginx; chown root:root /etc/logrotate.d/nginx
```

## What makes privmap different

LinPEAS, LinEnum, and BeRoot enumerate findings as flat lists of independent
observations. They report that a file is world-writable, and separately that
the same file is executed by a root cron job. They do not connect those
facts; the analyst correlates them manually.

privmap treats privilege escalation as a graph reachability problem. Each
finding is a node or an edge. The question moves from "what
misconfigurations exist" to "given this user, what is reachable and through
what sequence of relationships."

## Where to next

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Quickstart](quickstart.md)**

    Install and run your first scan in five minutes.

-   :material-book-open-page-variant: **[Live analysis](usage/live-analysis.md)**

    Scan the system you are running on.

-   :material-archive: **[Snapshot mode](usage/snapshot-mode.md)**

    Collect on one host, analyze offline on another.

-   :material-graph: **[Graph model](concepts/graph-model.md)**

    Nodes, edges, sinks, sources. What privmap actually builds.

-   :material-format-list-numbered: **[CLI reference](reference/cli.md)**

    Every flag, every default.

-   :material-shield-alert: **[Scope and limitations](limitations.md)**

    What privmap does, what it does not, and where it is best-effort.

</div>

## Project status

privmap is open source under the MIT license. The 1.x line is stable for
the core graph model and CLI surface. See the [changelog](changelog.md)
for release history and the [security policy](security.md) for
vulnerability reporting.
