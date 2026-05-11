# Installation

## Requirements

- Linux. privmap analyzes Linux systems; macOS and Windows are not supported
  targets.
- Python 3.8 or later.
- Root privileges to scan a live system for complete results. privmap will
  run as a regular user but cannot read `/etc/shadow`, walk all of `/etc`,
  enumerate other users' processes, or list `/var/spool/cron/crontabs`, and
  its findings will be incomplete.

The collector script for [snapshot mode](usage/snapshot-mode.md) needs only
a POSIX shell. No Python on the target.

## From PyPI

```bash
pip install privmap
```

privmap depends on [`networkx`](https://networkx.org) for the in-memory
graph and [`rich`](https://rich.readthedocs.io) for the terminal renderer.

## From source

```bash
git clone https://github.com/isaacc2/privmap.git
cd privmap
pip install -e .
```

To run the test suite or contribute, install the dev extras:

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check privmap/
```

To build the documentation locally:

```bash
pip install -e ".[docs]"
mkdocs serve
# then open http://127.0.0.1:8000
```

## Verifying the install

```bash
privmap --version
```

Should print `privmap <version>`. If the command is not found, ensure the
script directory of your Python install is on `PATH` (often `~/.local/bin`
for user installs).

## Running with sudo

The common pattern is:

```bash
sudo privmap
```

This gives privmap read access to `/etc/shadow`, every cron and systemd
unit, and the `/proc` entries of other users' processes. Findings without
root are still useful but partial; privmap will log a `WARNING` for each
privileged source it could not read.
