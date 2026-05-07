# Changelog

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