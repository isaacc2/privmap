# CI/CD integration

privmap is designed to be runnable as a gate in a deployment pipeline,
infrastructure-as-code workflow, or hardening regression check.

## Exit codes

```bash
sudo privmap --exit-code --min-severity critical
```

Returns `1` if any path at or above the specified severity is found, `0`
otherwise. This is the only flag that turns findings into a non-zero exit;
without it, a successful run is always `0` regardless of findings.

Common thresholds:

| Severity      | Recommended use                                           |
|---------------|-----------------------------------------------------------|
| `critical`    | Hard fail in production deploy gates.                     |
| `high`        | Fail in pre-prod, warn in prod.                           |
| `medium`      | Useful for security regression PRs.                       |
| `low`/`info`  | Reporting only. Too noisy to gate on.                     |

## GitHub Actions

A minimal integration:

```yaml
name: Privilege check

on:
  schedule:
    - cron: "0 7 * * 1"   # weekly Monday 07:00 UTC
  workflow_dispatch:

jobs:
  privmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install privmap
        run: pip install privmap

      - name: Run privmap
        run: |
          sudo privmap \
              --exit-code \
              --min-severity high \
              --output json \
              > privmap-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: privmap-report
          path: privmap-report.json
```

`if: always()` ensures the artifact is uploaded even when the run fails
the gate, so reviewers have the JSON to look at.

## GitLab CI

```yaml
privmap:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install privmap
  script:
    - privmap --exit-code --min-severity high --output json > report.json
  artifacts:
    when: always
    paths:
      - report.json
    expire_in: 30 days
```

## Snapshot-based pipelines

For air-gapped or production targets, run the collector on the host and
analyze in CI:

```bash
# On the target (manual or via configuration management):
sudo /opt/privmap/collect.sh
scp privmap_snapshot_*.tar.gz analysis-host:/incoming/

# On the analysis host or CI runner:
privmap \
    --snapshot /incoming/privmap_snapshot_target_20260507.tar.gz \
    --exit-code \
    --min-severity high \
    --output json > report.json
```

This pattern keeps privmap (and Python) entirely off the production host.

## Diffing reports over time

To track whether a system is regressing, save the JSON output to a known
location and diff successive runs:

```bash
sudo privmap --output json > /var/log/privmap/$(date +%Y%m%d).json
diff <(jq -S .paths /var/log/privmap/20260501.json) \
     <(jq -S .paths /var/log/privmap/20260507.json)
```

privmap does not ship a built-in diff mode in 1.x. This idiom is the
common substitute.

## Operational notes

- **Run as root.** Without it, the report is partial and may pass a gate
  that would otherwise fail.
- **Stable defaults.** The set of source users, sinks, and scan paths is
  stable across patch releases. Pin a major version (`privmap>=1,<2`) in
  your CI requirements to avoid behavior changes in 2.x.
- **Use `--scan-paths`** to keep CI runs fast. A focused scan of `/etc`
  and `/usr` typically completes in seconds; the full default scan can
  take a minute on a busy server.
- **Capture stderr.** Warnings about unreadable inputs (cron dirs, ACL
  timeouts) are written to stderr, not stdout. A clean stdout/JSON does
  not imply a complete scan.
