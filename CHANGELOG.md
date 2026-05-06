# Changelog

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