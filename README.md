<p align="left">
  <img src="https://raw.githubusercontent.com/isaacc2/privmap/main/logo/logo.png" alt="privmap" width="220">
</p>

[![tests](https://github.com/isaacc2/privmap/workflows/tests/badge.svg)](https://github.com/isaacc2/privmap/actions)
[![PyPI version](https://badge.fury.io/py/privmap.svg)](https://pypi.org/project/privmap/)
[![Documentation](https://readthedocs.org/projects/privmap/badge/?version=latest)](https://privmap.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/privmap.svg)](https://pypi.org/project/privmap/)

# privmap

**Find Linux privilege escalation paths by modeling permissions as a graph.**

privmap reads the live configuration of a Linux system: users, groups, sudo
rules, file permissions, cron jobs, systemd units, capabilities, and running
processes. It assembles them into a directed property graph, then traces
concrete escalation paths from each non-privileged user to root and other
high-value sinks.

```
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

Where flat-list scanners like LinPEAS report *"this file is world-writable"*
and *"this cron job runs as root"* as separate observations, privmap connects
them into the single chain that actually represents the escalation.

## Install

```bash
pip install privmap
```

Requires Python 3.8 or later. From source: `git clone … && pip install -e .`.

## Run

```bash
sudo privmap                                       # full scan, every user
sudo privmap --user www-data --user bob            # specific users
sudo privmap --min-severity high                   # filter by severity
sudo privmap --output json > report.json           # SIEM ingestion
sudo privmap --exit-code --min-severity critical   # CI/CD gate
```

For offline / forensic analysis, run the collector on the target and analyze
the snapshot on your workstation:

```bash
sudo ./collect.sh                                                   # on target
privmap --snapshot ./privmap_snapshot_target_20260507.tar.gz        # on analyst host
```

The collector is POSIX-compliant and has no runtime dependencies on the
target host.

## Documentation

Full documentation lives at **<https://privmap.readthedocs.io/>**. Start with
the [quickstart](https://privmap.readthedocs.io/en/latest/quickstart/), or
jump straight to the
[graph model](https://privmap.readthedocs.io/en/latest/concepts/graph-model/),
[CLI reference](https://privmap.readthedocs.io/en/latest/reference/cli/),
[scoring rules](https://privmap.readthedocs.io/en/latest/concepts/scoring/),
[CI/CD integration](https://privmap.readthedocs.io/en/latest/usage/ci-integration/),
or [known limitations](https://privmap.readthedocs.io/en/latest/limitations/).

## Scope

privmap is a **structural** analysis tool for local Linux privilege
relationships. It does not perform network enumeration, run exploits, cover
Windows or macOS, or match binary versions against a CVE database. Pair it
with a vulnerability scanner for full coverage.

## Use cases

- **System hardening.** Validate least-privilege configurations and catch
  unintended escalation paths after changes.
- **Penetration testing.** Replace manual enumeration with deterministic
  path mapping.
- **Incident response.** Reconstruct how an attacker may have escalated
  privileges on a compromised host.
- **Education and CTF.** Visualise permission chains that are hard to reason
  about manually.

## Contributing

Issues and pull requests are welcome. See
[CONTRIBUTING](https://privmap.readthedocs.io/en/latest/contributing/) for
development setup. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
