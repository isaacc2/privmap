# Known limitations

privmap is honest about where it is best-effort. This page enumerates
the classes of finding where you should interpret the report with care.

## Scope

privmap analyses local Linux privilege relationships. It explicitly
does not:

- Perform network enumeration or remote service fingerprinting.
- Run exploits or attempt actual privilege escalation.
- Cover Windows or macOS.
- Match installed binary versions against a CVE database.
- Inspect kernel exploits, container escapes, or hypervisor flaws.

It is a structural analysis tool. Pair it with a vulnerability scanner
and a network mapper for full coverage.

## Argument-restricted sudo rules

Rules like `sudo /usr/bin/systemctl restart nginx` receive a reduced
exploitability score but are not fully argument-validated. A rule with
restricted arguments may still appear as a finding if the binary is on
the GTFOBins shell-escape list. privmap errs on the side of surfacing.

Full sudoers argument parsing (with glob, quote, and `EXEC:` / `SETENV:`
tag semantics) is hard to do correctly with regex and is currently
best-effort. If you depend on argument restriction for security,
validate the rule manually rather than relying on the scoring
difference.

## Third-party capability binaries

The known-safe allowlist for capability binaries covers standard system
tools (`snap-confine`, `ping`, `mtr`, `chronyd`, and similar) on
Debian, Ubuntu, RHEL, and Fedora defaults. Capability binaries from
third-party packages are **not** on the allowlist and may produce false
positives if they legitimately need a dangerous capability for internal
use.

If you see a third-party capability binary repeatedly flagged on
systems where it is known to be intentional, open a GitHub issue with
the binary name, package source, and what it uses the capability for.
The allowlist is updated regularly.

## Snapshot mode conservatism

Snapshot mode falls back to conservative behavior when a check cannot
be performed against an archive:

- Per-user `CAN_EXEC` checks on capability binaries require the
  snapshot's `permissions.txt`. If absent, the edge is not emitted.
- Symlink resolution uses `readlink -f` (transitive) in snapshot mode
  and raw `os.readlink` (single-step) in live mode. Results may differ
  on systems with chained symlinks.
- Filesystem permission checks for sticky-bit handling are limited to
  what was captured.

Live mode is always more accurate. Use snapshot mode when live access
is impossible (incident response, air-gapped systems) and interpret the
results accordingly.

## Cron command parsing

Cron and systemd command extraction handles shell separators (`&&`,
`||`, `;`, `|`), drops leading env-var assignments, and only emits
absolute paths as `EXECUTES` targets. It does not:

- Resolve relative `$PATH` lookups.
- Expand `$VARIABLE` references inside the command.
- Parse complex pipelines beyond the head of each segment.

A cron entry that invokes a binary via `$PATH` lookup, or whose actual
target is deeply embedded in a shell pipeline, may not produce an
`EXECUTES` edge.

## No CVE matching

privmap does not check binary versions against known vulnerabilities.
Specifically:

- pkexec is filtered as auth-required. The PwnKit family
  (CVE-2021-4034 et al.) requires a vulnerability scanner to detect.
- `sudo` itself is filtered as auth-required. Baron Samedit
  (CVE-2021-3156) and similar require a vulnerability scanner.
- Kernel SUID exploit primitives (Dirty Cow, Dirty Pipe, and similar)
  are out of scope entirely.

Pair privmap with a CVE scanner (Trivy, Grype, or your distribution's
auditing tool) for version-based findings.

## Filesystem walk scope

The default scan paths (`/etc`, `/usr`, `/opt`, `/tmp`, `/var`)
deliberately exclude `/home`. Many real escalation paths originate in
user home directories (writable scripts, SSH keys, `.bashrc` injection
on shared hosts). Add `/home` to `--scan-paths` if your threat model
includes multi-user systems.

Large directories with no privilege relevance are pruned (`/usr/share`,
`/var/log`, `/snap`, and similar). If you are auditing an unusual
system where these contain escalation-relevant files, the prune list is
hardcoded in `privmap.ingestion.filesystem.EXCLUDED_PATH_PREFIXES` and
would need a PR to extend.

## Group ACLs

Group-ACL entries (`group:NAME:rw-` in `getfacl` output) are expanded
into per-member `CAN_WRITE` edges. If group membership changes between
the ingestion run and the actual exploit attempt, the report may
overstate or understate access. Re-run after any `gpasswd` activity.

## Performance on very large filesystems

The filesystem walk is single-threaded and not cached between runs. On
a server with millions of files in the scan paths, expect the walk to
be the dominant phase. Tightening `--scan-paths` is the main lever.
Parallel walk support is on the roadmap but not in 1.x.
