# Live analysis

Live analysis runs privmap directly on the system you want to assess. It
reads from `/etc`, `/proc`, `/var/spool/cron`, and the configured scan
paths.

## Basic invocation

```bash
sudo privmap
```

This is equivalent to:

```bash
sudo privmap \
    --output cli \
    --min-severity low \
    --max-depth 10 \
    --scan-paths /etc,/usr,/opt,/tmp,/var
```

## Filtering by user

By default privmap traces paths from every non-privileged principal it can
identify. Any user with `uid != 0` and a real shell qualifies; accounts
with `/usr/sbin/nologin` or `/bin/false` are skipped automatically.

To restrict the scan to specific source users:

```bash
sudo privmap --user www-data
sudo privmap --user www-data --user bob       # repeat the flag
sudo privmap -u www-data -u bob               # short form
```

This narrows the report when investigating a specific account.

## Filtering by severity

```bash
sudo privmap --min-severity high
```

Choices: `critical`, `high`, `medium`, `low`, `info`. The default is `low`,
which hides only `info`-tier findings.

For how severity is computed, see
[Scoring and severity](../concepts/scoring.md).

## Tuning the scan

### Scan paths

```bash
sudo privmap --scan-paths /etc,/usr/local,/opt
```

By default privmap walks `/etc`, `/usr`, `/opt`, `/tmp`, and `/var`. Narrow
this on systems with very large `/var` (mail spools, log archives) to keep
the filesystem walk fast.

`/home` is not in the defaults because user home directories contain a
high volume of files relative to escalation-relevant content. Add it
explicitly to look for writable scripts or stale SSH keys:

```bash
sudo privmap --scan-paths /etc,/usr,/opt,/tmp,/var,/home
```

### Traversal depth

```bash
sudo privmap --max-depth 8
```

The DFS will not extend a path beyond this many hops. Default is `10`,
which catches all realistic chains. Lowering this is a performance lever
on dense graphs; raising it is rarely useful.

### Verbosity

```bash
sudo privmap -v          # info-level logs
sudo privmap -vv         # debug-level logs
sudo privmap --quiet     # suppress the progress spinner
```

With `-v` or `-vv` the progress spinner is suppressed automatically since
the log lines convey the same information more durably.

## Output formats

```bash
sudo privmap --output cli           # rich terminal (default)
sudo privmap --output json          # structured JSON
sudo privmap --output markdown      # GitHub-flavored markdown
```

See [Output formats](output-formats.md) for the schema of each.

## Exit codes

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| `0`  | Success. No paths at or above `--min-severity` (when `--exit-code`).    |
| `1`  | One or more paths at or above `--min-severity` (when `--exit-code`).    |
| `1`  | An unexpected error occurred.                                           |
| `130`| Interrupted (Ctrl-C).                                                   |

Without `--exit-code`, privmap returns `0` on a successful run regardless
of findings. With `--exit-code`, it returns `1` when paths are present.
See [CI/CD integration](ci-integration.md).

## Graph export

To dump the full graph for use in other tools (Neo4j queries, Cypher
transforms, custom dashboards):

```bash
sudo privmap --export-graph graph.json
```

The structure is documented under
[Graph model](../concepts/graph-model.md).

## Running unprivileged

privmap will run as a regular user. Several inputs require root to read.
The shadow file, other users' `/proc` entries, and
`/var/spool/cron/crontabs` will be skipped with a `WARNING`. The graph
will still build and analysis will still run, but the results are
incomplete. For any real assessment, use `sudo`.
