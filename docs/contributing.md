# Contributing

Thanks for considering a contribution to privmap. For the 
bigger picture see [Architecture](reference/architecture.md).

## Development setup

```bash
git clone https://github.com/isaacc2/privmap.git
cd privmap
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

This installs privmap in editable mode along with `pytest`,
`pytest-cov`, `mypy`, and `ruff`.

## Running the test suite

```bash
pytest tests/ -v
```

## Linting and type checking

```bash
ruff check privmap/
mypy privmap/
```

Both should be clean before opening a PR.

## Building the docs locally

```bash
pip install -e ".[docs]"
mkdocs serve
# open http://127.0.0.1:8000
```

`mkdocs serve` watches the `docs/` tree and rebuilds on save.

## What we are looking for

Good first contributions:

- **Allowlist additions.** A binary that should be on
  `AUTH_REQUIRED_SUID` or `KNOWN_SAFE_CAP_BINARIES`. Include the
  package source and a one-line rationale.
- **GTFOBins synchronisation.** Updates to `GTFOBINS_SUID` or
  `SUDO_SHELL_ESCAPE` based on upstream changes.
- **Test fixtures.** A sample snapshot tarball with a known-correct
  expected set of paths.
- **Documentation.** Typo fixes, clearer explanations, missing examples.

Larger work to discuss in an issue first:

- A new ingester (AppArmor, SELinux, container runtimes).
- A new output format (SARIF is a known want).
- A change to the scoring model.
- Public-API surface changes.

## Coding conventions

- Python 3.8-compatible syntax. Use `from __future__ import annotations`
  for modern type hints.
- Type-annotate new code. Mypy is run in CI.
- Default to no comments. Only annotate code when the *why* is
  non-obvious.
- Match the existing module structure. Ingesters live in `ingestion/`,
  graph primitives in `graph/`, analysis in `analysis/`, output in
  `output/`. The CLI in `cli.py` is thin.
- Edits to ingestion modules should be testable against fixture data.

## Commit and PR style

- Keep PRs focused. One logical change per PR.
- Reference any related issue in the description.
- For correctness fixes (false positives or negatives), include a test
  or a fixture demonstrating the prior behavior.
- For new features, include documentation updates in the same PR.

## Reporting issues

Bug reports are most useful when they include:

- privmap version (`privmap --version`).
- Distribution and kernel (`/etc/os-release`, `uname -a`).
- The command that produced the issue.
- The relevant excerpt of the output (with `-vv` if possible).
- For false positives or negatives, the specific path or finding and
  why you believe the analysis is wrong.

Security-sensitive issues go to the [security policy](security.md), not
the public issue tracker.
