# Changelog

## v1.0.4

### Correctness
- Auth-required SUID binaries (`su`, `pkexec`, `sudo`, `doas`, `passwd`, `chsh`, `mount`, `ssh-agent`, etc.) are no longer reported as free escalation paths. They are SUID by design and gate access behind a credential prompt; flagging them produced a critical-severity finding for every user on every system. Specific CVEs against these binaries (e.g. PwnKit) are out of scope — privmap does not do version-based CVE matching.
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

## v1.0.0 — Initial release

- Graph-based privilege escalation analysis for Linux
- Ingestion modules: identity (passwd, group, shadow, sudoers with alias support), filesystem (SUID/SGID, world-writable, ACLs, symlinks), execution (cron, systemd, init.d), capabilities, processes
- DFS reachability traversal with edge-semantic filtering
- Dual-axis scoring (exploitability × impact) with severity ratings
- Output formats: rich CLI, JSON, Markdown
- Snapshot mode with POSIX-compliant collector script
- Allowlist for known-safe capability binaries (snap-confine, ping, mtr, etc.)
- Permission-aware CAN_EXEC edge creation
- Argument-restricted sudo rule scoring