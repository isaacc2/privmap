# Changelog

## v1.0.7

### Branding
- Added project logo. Rendered as a hero image at the top of the README (via absolute `raw.githubusercontent.com` URL so it also displays on the PyPI page), as the nav-bar logo on the MkDocs Material docs site, and as the browser-tab favicon. Source kept at `logo/logo.png`; downsized 192x192 favicon staged at `docs/assets/favicon.png`.

### Testing
- Added 90 new tests across four files, lifting coverage of security-critical and recently-changed code from minimal to substantive:
    - `tests/test_safe_extract.py` (14 tests) pins down the tarfile path-traversal defenses in `cli._safe_extract_tar`: absolute path rejection, parent-directory traversal, escaping symlinks and hardlinks, special-file refusal, member-count and byte-size limits.
    - `tests/test_command_parsing.py` (23 tests) covers cron and systemd command extraction, including env-var stripping, shell-segment splitting (`&&`, `||`, `;`, `|`), and that path arguments like `/etc` are not treated as executables.
    - `tests/test_sudoers_parsing.py` (15 tests) regression-locks the v1.0.1 fixes: `NOPASSWD:` detected at tag position rather than substring, locked accounts (`!`, `!!`, `*`) not misclassified as empty-password, and correct runas resolution.
    - `tests/test_traversal_filters.py` (38 tests) parametrizes over the `AUTH_REQUIRED_SUID`, `GTFOBINS_SUID`, and `KNOWN_SAFE_CAP_BINARIES` allowlists to lock in current filter behavior, plus sink and source predicate coverage.
- Total test count is now 102 (was 12).

## v1.0.6

### Packaging
- Added PyPI trove classifiers (Development Status, Intended Audience, License, Operating System, Python versions 3.8 to 3.13, Topic). These power PyPI's sidebar filters and search, and unblock the `pyversions` shield on the README which previously displayed "missing" because shields.io reads classifiers, not `requires-python`.
- Added `keywords` to package metadata (`security`, `linux`, `privilege-escalation`, `graph`, `pentesting`, `hardening`) to improve PyPI search discoverability.

No code changes in this release.

## v1.0.5

### Documentation
- Added a full documentation site built with MkDocs Material, hosted on Read the Docs at <https://privmap.readthedocs.io/>. Covers installation, quickstart, live and snapshot analysis modes, CI/CD integration, output formats, graph model, scoring, path validation, CLI reference, architecture, Python API, known limitations, FAQ, security policy, and contributing.
- README rewritten as a focused project hook (badges, one-line description, install, quickstart, links to the docs site) rather than as the primary manual. Deep content lives in the docs.
- Reworded the package short description from "Linux privilege graph engine - model effective access, trace escalation paths." to "Find Linux privilege escalation paths by modeling permissions as a graph."

### Packaging
- Added a `docs` extras group: `pip install -e ".[docs]"` installs `mkdocs`, `mkdocs-material`, `mkdocs-include-markdown-plugin`, and `pymdown-extensions`.
- Added `[project.urls]` metadata for Homepage, Documentation, Repository, Issues, and Changelog. These surface as clickable links on the PyPI page.
- Added a `.readthedocs.yaml` build config so RTD builds are reproducible and the docs deps stay in sync with the project.

### Python API
- `privmap/__init__.py` now re-exports the stable public API: `GraphBuilder`, `PrivilegeGraph`, `Node`, `NodeType`, `Edge`, `EdgeType`, `EscalationPath`, `Severity`, `analyze_paths`, `export_json`, `export_markdown`, `__version__`. Programmatic users can now write `from privmap import GraphBuilder, analyze_paths`.

## v1.0.4

### Correctness
- Auth-required SUID binaries (`su`, `pkexec`, `sudo`, `doas`, `passwd`, `chsh`, `mount`, `ssh-agent`, etc.) are no longer reported as free escalation paths. They are SUID by design and gate access behind a credential prompt; flagging them produced a critical-severity finding for every user on every system. Specific CVEs against these binaries (e.g. PwnKit) are out of scope; privmap does not do version-based CVE matching.
- An unreadable `/var/spool/cron/crontabs` (mode `0730 root:crontab` on Debian-family systems) no longer crashes the run. Now logs a warning and continues with a partial scan.

### UX
- Added a live progress spinner during ingestion and analysis so the tool no longer appears frozen on long scans. Reports the active phase (identity, filesystem walk, execution contexts, capabilities, processes, path tracing) and a periodic file count during the filesystem walk. Renders to stderr so it does not pollute `--output json` / `--output markdown` redirects, and is suppressed automatically with `-v`/`-vv`, `--quiet`, or in non-TTY environments.
- Added `--quiet` / `-q` to suppress the progress spinner unconditionally.

## v1.0.3

### Correctness
- Handling for SUID_EXEC edges (reduced false flags)

## v1.0.2

### Hygiene
- Minor version control reconfiguration

## v1.0.1

### Security
- Fixed path traversal vulnerability in snapshot extraction (CVE-2007-4559 class). Tar extraction now rejects absolute paths, parent-directory traversal, escaping symlinks and hardlinks, and special files, and enforces 2 GiB / 200k member limits against tar bombs.

### Correctness
- `getcap -r` now honors the configured root path instead of always scanning `/`. Snapshot mode no longer leaks to the host filesystem.
- `_user_can_execute` now fails closed on stat errors instead of fabricating CAN_EXEC edges.
- Snapshot mode now performs real per-user execute checks against captured permissions instead of emitting CAN_EXEC for every non-root user.
- World-writable files inside sticky directories (e.g. `/tmp/*`) no longer produce CAN_WRITE edges, since users cannot replace files they do not own.
- `getfacl` timeouts now log at WARNING with actionable advice instead of being silently swallowed.
- ACL parsing now handles `group:NAME:rw-` entries and expands them into per-member CAN_WRITE edges.
- Shadow file parsing no longer misclassifies locked accounts (`!`, `*`) as having empty passwords.
- `NOPASSWD:` / `PASSWD:` sudoers tags are now parsed via anchored regex, so path arguments containing the literal string no longer flip the flag.
- Cron and systemd command parsing now extracts only the actual binary head per shell segment, skipping env-var assignments and splitting on `&&`, `||`, `;`, `|`. Commands like `find /etc -name foo` no longer create bogus FILE nodes for `/etc`.

### Hygiene
- Removed duplicated `KNOWN_SAFE_CAP_BINARIES` set; canonical version now lives in the capabilities module.
- JSON export `version` field now sources from `privmap.__version__` instead of a hardcoded duplicate.

## v1.0.0 - Initial release

- Graph-based privilege escalation analysis for Linux
- Ingestion modules: identity (passwd, group, shadow, sudoers with alias support), filesystem (SUID/SGID, world-writable, ACLs, symlinks), execution (cron, systemd, init.d), capabilities, processes
- DFS reachability traversal with edge-semantic filtering
- Dual-axis scoring (exploitability × impact) with severity ratings
- Output formats: rich CLI, JSON, Markdown
- Snapshot mode with POSIX-compliant collector script
- Allowlist for known-safe capability binaries (snap-confine, ping, mtr, etc.)
- Permission-aware CAN_EXEC edge creation
- Argument-restricted sudo rule scoring