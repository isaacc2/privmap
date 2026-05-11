# Changelog

## v2.0.0

A major release bridging the LinPEAS coverage gap. Adds 16 new node types, 5 new edge types, 11 new ingester modules, and a corresponding expansion of `collect.sh`. Existing JSON consumers continue to work; the `version` field in JSON output now reads `2.0.0`.

### New ingesters
- **boot.py**: login-time scripts (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/skel/*`), library-loading control (`/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*`), polkit rules (`/etc/polkit-1/rules.d/*`, `/usr/share/polkit-1/rules.d/*`). Each script and config file becomes a node; writability emits `CAN_WRITE` from the appropriate principals and the script emits `EXECUTED_AT_LOGIN` or `INFLUENCES_EXEC` to root, so the graph traversal can find chains like `unprivileged user -> CAN_WRITE -> /etc/profile.d/foo.sh -> EXECUTED_AT_LOGIN -> root`.
- **auth.py**: doas configuration (`/etc/doas.conf`) with full rule parsing and `nopass` flag detection; sudo version capture (no CVE matching, just the version string); sudoers file *permissions* (writable `/etc/sudoers` or `/etc/sudoers.d/*` is its own immediate path to root); `/etc/security/*` (PAM-adjacent limits and access controls).
- **ssh.py**: `sshd_config` risky-setting detection (`PermitRootLogin yes`, `PasswordAuthentication yes`, `PermitEmptyPasswords yes`); host key file permissions (`/etc/ssh/ssh_host_*_key` should be 0600 root:root); per-user `~/.ssh/authorized_keys` and `id_*` keys with writability flagged as `INFLUENCES_EXEC` to that user.
- **network.py**: NFS exports (`/etc/exports`) with `no_root_squash` / `no_all_squash` detection; fstab (`/etc/fstab`) `nosuid`-missing on `/tmp`/`/home` and `no_root_squash` on NFS mounts; r-command host trust (`/etc/hosts.equiv`, `~/.rhosts`); `/etc/hosts` writability; listening TCP/UDP ports parsed from `/proc/net/{tcp,tcp6,udp,udp6}` with inode-to-pid resolution in live mode.
- **container.py**: detects whether the analyzed system is running inside a container (Docker, Podman, LXC, Kubernetes) via `/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup` patterns. Flags container-breakout artifacts (Docker socket inside the container, full effective capabilities on PID 1).
- **secrets.py**: scans `/proc/[pid]/environ` for processes exposing credentials via standard env-var keys (PASSWORD, TOKEN, API_KEY, AWS_SECRET, DATABASE_URL, etc.) and emits a `SECRET_FINDING` node with an `EXPOSES` edge from the owning process.
- **path_abuse.py**: parses `$PATH` from `/etc/environment` and `/etc/login.defs`. Each PATH directory becomes a `PATH_DIR` node; the walker flags writable shell scripts on PATH, broken symlinks on PATH, and PATH dirs writable by non-root.
- **pam.py**: parses `/etc/pam.d/*` and flags `pam_rootok.so` on services other than `su`/`sudo`, `pam_permit.so`, `nullok` on `pam_unix.so`, and `pam_wheel.so` without explicit `group=` restriction. Writability of PAM files is also flagged.

### Graph model
- 12 new `NodeType` values: `PROFILE_SCRIPT`, `LDPRELOAD_FILE`, `POLKIT_RULE`, `PAM_FILE`, `SSH_KEY`, `NFS_EXPORT`, `CONTAINER_MARKER`, `NETWORK_LISTENER`, `PATH_DIR`, `LOGIN_HOOK`, `DOAS_RULE`, `SECRET_FINDING`.
- 5 new `EdgeType` values: `EXECUTED_AT_LOGIN`, `INFLUENCES_EXEC`, `LISTENS_ON`, `TRUSTS`, `EXPOSES`.
- Sinks now include `DOAS_RULE` with target=root, and `CONTAINER_MARKER` with breakout artifacts present.

### Filesystem detection
- **Group-writable files** are now first-class. The walk emits `CAN_WRITE` from each user in the file's group, with proper sticky-bit suppression. This closes the most common privmap blind spot (e.g. a logrotate config owned `root:adm` mode 0664 with wwwdev in the adm group is now correctly flagged).
- New snapshot inputs: `suid/group_writable_files.txt` and `suid/group_writable_dirs.txt` (format: `mode owner group path`). The new `collect.sh` produces these.

### Execution-arg semantics
- Cron and systemd command parsers now emit `INFLUENCES_EXEC` edges from config-file path arguments back to the running cron/unit. A cron entry like `/usr/sbin/logrotate /etc/logrotate.d/myapp` now produces an edge `file:/etc/logrotate.d/myapp -INFLUENCES_EXEC-> cron:...` so a writable config in `/etc/*.d/` chains correctly through the privileged execution.
- Cron periodic-dir parser (`/etc/cron.{daily,hourly,weekly,monthly}/*`) now reads each script's content for the same analysis, so chains like the v1 demo (`wwwdev -> adm -> /etc/logrotate.d/myapp -> /etc/cron.daily/myapp-logs -> root`) close end-to-end.

### Collector
- `collect.sh` v2 gathers group-writable files, login-time scripts, ld.so configuration, polkit rules, doas config, sudo version, PAM files, `/etc/security`, sshd_config + host key metadata, NFS exports, fstab, host-trust files, `/etc/hosts`, `/proc/net/tcp[6]` and `/proc/net/udp[6]`, container markers, `/proc/1/cgroup`, and per-process environ at `/proc/[pid]/environ.txt`. All files land at their natural target-system paths under `OUTDIR/`, so ingesters work identically in live and snapshot mode.

### Scoring and remediation
- Scoring axes extended with `EXECUTED_AT_LOGIN` (waiting penalty similar to cron) and `INFLUENCES_EXEC` (small situational penalty) factors. Doas `nopass` treated like sudo `nopasswd`.
- Remediation now emits specific commands for group-writable, owner-writable, EXECUTED_AT_LOGIN, INFLUENCES_EXEC, TRUSTS, and EXPOSES findings.

### Expansion (Batches K-R)
- **Sudo tokens**: enumerates `/var/run/sudo/ts/` and `/var/db/sudo/ts/`. Active timestamps are recorded as `active_sudo_token` property on the corresponding user node.
- **Kerberos ticket files**: scans `/tmp/krb5cc_*` and `/var/tmp/krb5cc_*`. Overly-readable cache files emit `INFLUENCES_EXEC` to the ticket's owner.
- **`/etc/profile` PATH manipulation detection**: flags login scripts that prepend `.`, `~`, or an empty entry to `$PATH`.
- **D-Bus policy analysis** (`dbus.py`): parses XML in `/etc/dbus-1/system.d/*.conf` and `/usr/share/dbus-1/system.d/*.conf`. Flags policies that grant `<allow send_destination="..."/>` without a method restriction, or `own="..."` to a non-root principal. Emits `INFLUENCES_EXEC` for over-permissive policies.
- **Systemd PATH overrides**: extracts `Environment="PATH=..."` from unit files. When the unit runs as root and invokes binaries by unqualified name, the override is part of the chain.
- **Wildcard injection detection**: flags cron and systemd commands invoking `tar`, `rsync`, `chmod`, `chown`, `7z`, `zip`, `scp` with an unquoted `*` in argv. Property `wildcard_injection_risk` lands on the `CRON_JOB` / `SYSTEMD_UNIT` node.
- **Inetd / xinetd services** (`inetd.py`): parses `/etc/inetd.conf` and `/etc/xinetd.d/*`. Each enabled service becomes an `INETD_SERVICE` node with `RUNS_AS` and `EXECUTES` edges, same shape as systemd units.
- **AppArmor profiles** (`apparmor.py`): enumerates `/etc/apparmor.d/*`, captures profile state from `/sys/kernel/security/apparmor/profiles`. Flags profiles in complain mode and writable profile files.
- **Container writable bind mounts**: extends `container.py` to parse `/proc/mounts` and flag writable bind mounts on `/host`, `/mnt`, `/var/lib`, or `/` that lack `nosuid`. Emits `MOUNT` nodes with `INFLUENCES_EXEC` to root.

### Chain wiring for previously-orphan node types
- **`PATH_DIR` integration**: when a cron job or systemd unit invokes a binary by unqualified name, every `PATH_DIR` node now emits `INFLUENCES_EXEC` to that cron/unit. Combined with the existing CAN_WRITE machinery, a writable `/usr/local/bin` becomes a real escalation chain to any root cron using unqualified commands.
- **`PATH_DIR` writability**: `path_abuse.py` now emits its own `CAN_WRITE` edges from the appropriate principals when a PATH directory is world- or group-writable, instead of relying solely on the filesystem ingester (which doesn't know about PATH semantics).
- **`SSH_KEY` `authorized_keys` chain**: writability of root's `~/.ssh/authorized_keys` now closes a chain from writer → key file → root via the existing `INFLUENCES_EXEC` to target user. (The edge was emitted in the initial v2 batch, but no test verified the chain closed end-to-end. There is now a test for that.)

### New node types (16)
`PROFILE_SCRIPT`, `LDPRELOAD_FILE`, `POLKIT_RULE`, `PAM_FILE`, `SSH_KEY`, `NFS_EXPORT`, `CONTAINER_MARKER`, `NETWORK_LISTENER`, `PATH_DIR`, `LOGIN_HOOK`, `DOAS_RULE`, `SECRET_FINDING`, `DBUS_POLICY`, `INETD_SERVICE`, `APPARMOR_PROFILE`, `MOUNT`.

### Tests
- 39 new tests across `tests/test_v2_ingesters.py` (20) and `tests/test_v2_expansion.py` (19), covering every new ingester plus chain-wiring integration tests. The full demo chain (group-writable logrotate config + root cron invoking logrotate against it) now has a dedicated end-to-end test that verifies `find_escalation_paths` produces at least one path. **Total test count: 141 (was 102 in v1.0.8).**

### Known gaps (deliberately out of scope)
- Application-specific config-file secret scanning (100+ check categories in LinPEAS). Use `gitleaks`, `trufflehog`, or similar.
- Cloud metadata enumeration (AWS IMDS, GCP metadata, Azure IMDS). Requires network egress, which privmap does not do.
- CVE matching against captured binary versions. Pair with `trivy`, `grype`, or a CVE-aware scanner.
- Browser data, mail spools, password searches in shell history. Out of scope.
- Deep D-Bus method semantics, full sudoers grammar, full PAM stack evaluation. All best-effort.

## v1.0.8

### Documentation
- Fixed broken README hero image. The v1.0.7 README pointed at `main/logo/logo.png`, but the `logo/` directory was removed before the v1.0.7 commit and the image only ships under `docs/assets/`. The README and PyPI project page now resolve the hero from `main/docs/assets/logo.png`.
- Added the logo as a hero image on the docs site landing page (`docs/index.md`), matching the README placement.

No code changes in this release.

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