# Quickstart

From `pip install` to a meaningful report in about five minutes.

## 1. Install

```bash
pip install privmap
```

See [Installation](installation.md) for installation from source or setting
up the docs build.

## 2. Run a full scan

```bash
sudo privmap
```

privmap walks `/etc`, `/usr`, `/opt`, `/tmp`, and `/var` by default. It
reads identity data (passwd, group, shadow, sudoers), execution contexts
(cron, systemd, init.d), and Linux capabilities, then traces escalation
paths from every non-privileged user toward root and other high-value
sinks.

A progress spinner shows the active phase. On a typical Debian server this
completes in 30 to 90 seconds.

## 3. Read the output

The default renderer groups paths by source user and severity. Each path
is a chain of relationships ending at a sink:

```text
[CRITICAL] 2 escalation paths found for user: www-data

Path 1: www-data -> root (4 hops)
  www-data
    MEMBER_OF  group: adm
    CAN_WRITE  file: /etc/logrotate.d/nginx  (mode: 0664)
    EXECUTES   cron: /etc/cron.daily  (runs-as: root)
  -> root

  Risk: Writable logrotate config executed by root daily cron
  Remediation: chmod 644 /etc/logrotate.d/nginx
```

Each path includes:

- **Hops**: the alternating node and edge sequence from source to sink.
- **Risk**: a one-line explanation of why this is an escalation.
- **Remediation**: concrete commands to break the chain.
- **Scores**: exploitability and impact, each out of 10. See
  [Scoring and severity](concepts/scoring.md).

## 4. Common follow-up runs

Filter to a specific user:

```bash
sudo privmap --user www-data
```

Filter by severity (`critical`, `high`, `medium`, `low`, `info`):

```bash
sudo privmap --min-severity high
```

Get machine-readable output for a SIEM or downstream tooling:

```bash
sudo privmap --output json > report.json
sudo privmap --output markdown > report.md
```

Use in CI/CD with a non-zero exit on critical findings:

```bash
sudo privmap --exit-code --min-severity critical
```

See [Live analysis](usage/live-analysis.md) for the full set of options
and [Output formats](usage/output-formats.md) for the JSON schema.

## What's next

- [Snapshot mode](usage/snapshot-mode.md) for offline analysis.
- [Graph model](concepts/graph-model.md) for what privmap is actually
  building under the hood.
- [Known limitations](limitations.md) for where the analysis is best-effort,
  so you can interpret findings correctly.
