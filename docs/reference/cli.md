# CLI reference

Canonical list of every flag privmap accepts.

```text
privmap [OPTIONS]
```

## Global

| Flag                | Default  | Description                                                                |
|---------------------|----------|----------------------------------------------------------------------------|
| `--version`         |          | Print version and exit.                                                    |
| `-h`, `--help`      |          | Print help and exit.                                                       |
| `-v`, `--verbose`   | `0`      | Increase log verbosity. `-v` is INFO, `-vv` is DEBUG.                      |
| `-q`, `--quiet`     | `false`  | Suppress the progress spinner. Errors and warnings still go to stderr.     |

## Source selection

| Flag                              | Default | Description                                                            |
|-----------------------------------|---------|------------------------------------------------------------------------|
| `--snapshot PATH`                 |         | Analyze an offline snapshot tarball instead of live. See [snapshot mode](../usage/snapshot-mode.md). |
| `--user USERNAME`, `-u USERNAME`  | all     | Trace from this user. Repeatable. By default privmap traces every non-privileged user with a real shell. |

## Scan tuning

| Flag                  | Default                          | Description                                                  |
|-----------------------|----------------------------------|--------------------------------------------------------------|
| `--scan-paths PATHS`  | `/etc,/usr,/opt,/tmp,/var`       | Comma-separated paths to walk for filesystem ingestion.      |
| `--max-depth N`       | `10`                             | Maximum traversal depth (number of edges per path).          |

## Output

| Flag                       | Default  | Description                                                                          |
|----------------------------|----------|--------------------------------------------------------------------------------------|
| `--output FORMAT`, `-o`    | `cli`    | One of `cli`, `json`, `markdown`. See [output formats](../usage/output-formats.md).  |
| `--min-severity SEVERITY`  | `low`    | One of `critical`, `high`, `medium`, `low`, `info`. Hides paths below this tier.     |
| `--export-graph FILE`      |          | Write the full graph (all nodes, all edges) as JSON to `FILE`.                       |
| `--exit-code`              | `false`  | Return non-zero if any path at or above `--min-severity` is found.                   |

## Stream layout

| Stream | Contents                                                                            |
|--------|-------------------------------------------------------------------------------------|
| stdout | The report in the chosen output format.                                             |
| stderr | Progress spinner (when TTY and not `-q` or `-v`), logger output, warnings, errors.  |

This separation means `privmap --output json > report.json` works
correctly. The JSON is on stdout, everything else is on stderr.

## Examples

```bash
# Default. Scan everything, render to terminal.
sudo privmap

# A single user.
sudo privmap --user www-data

# CI gate that fails on critical findings only.
sudo privmap --exit-code --min-severity critical --output json > report.json

# Offline analysis of a snapshot from a different host.
privmap --snapshot ./privmap_snapshot_target_20260507.tar.gz \
        --output markdown > target-report.md

# Fast focused scan, debug logging.
sudo privmap --scan-paths /etc --user www-data -vv

# Dump the full graph for downstream tooling.
sudo privmap --export-graph graph.json --output json > paths.json
```
