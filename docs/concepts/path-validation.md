# Path validation

A candidate path is only reported if it survives a set of semantic
checks. Without these, the DFS would emit a large number of structurally
connected but practically meaningless chains. This page documents what
gets filtered and why.

## The write-execute chain check

A `CAN_WRITE` edge into a file is only useful if some privileged context
executes that file. If user -> file has no inbound `EXECUTES` edge and
the file does not appear in a downstream `RUNS_AS` or `EXECUTES` chain,
the write buys the attacker nothing. They can change the file contents,
but nothing runs it as anyone special.

The check, implemented in
`privmap.graph.traversal._validate_write_execute_chain`:

> For every `CAN_WRITE` edge in the path, require an inbound or
> outbound edge of one of the following types on the target node,
> **or** the very next hop in the path itself being one of these
> types:
>
> - `EXECUTES` (a cron, systemd unit, or init.d script runs the file)
> - `RUNS_AS` (the file is itself an execution context)
> - `EXECUTED_AT_LOGIN` (the file is sourced at user login)
> - `INFLUENCES_EXEC` (the file is a config arg, ld.so preload,
>   polkit rule, PAM stack, or NFS export that controls privileged
>   execution)

If none of those hold, the path is dropped.

The `EXECUTED_AT_LOGIN` and `INFLUENCES_EXEC` types were added in v2.0
to support chains like "writable `/etc/profile.d/foo.sh` is sourced
when root logs in" and "writable `/etc/logrotate.d/myapp` is invoked
by root cron via `logrotate /etc/logrotate.d/myapp`." Both are real
escalation paths and both require these edge types to close.

## The known-safe capability binary filter

Some Linux binaries carry dangerous capabilities (`cap_net_raw`,
`cap_sys_admin`, and similar) by design and use them internally without
exposing them to the caller. The `ping` family is the textbook example.

If a path traverses a `FILE` -> `CAPABILITY` edge where the file is on
the known-safe list (`KNOWN_SAFE_CAP_BINARIES` in
`privmap.ingestion.capabilities`), the path is dropped.

The list mirrors the approach taken by Lynis and
linux-exploit-suggester and covers standard Debian, Ubuntu, RHEL, and
Fedora package configurations.

## The auth-required SUID filter

Some SUID-root binaries (`su`, `sudo`, `pkexec`, `doas`, `passwd`,
`chsh`, `mount`, `ssh-agent`, and similar) are SUID by design and gate
access behind a credential prompt. Their existence on the system is not,
by itself, a privilege escalation path.

If a `SUID_EXEC` edge points at one of these binaries
(`AUTH_REQUIRED_SUID` in `privmap.graph.traversal`), the edge is skipped
during traversal.

Specific CVEs against these binaries (the PwnKit family against pkexec,
historic vulnerabilities in `su`) are out of scope for privmap. It does
not do version-based CVE matching. Pair privmap with a vulnerability
scanner if that capability is in your threat model.

## The GTFOBins SUID filter

Not every SUID binary allows arbitrary code execution as the file owner.
Many have narrow, well-defined functionality and do not give a shell
escape. privmap considers a `SUID_EXEC` edge a real escalation only when
the binary is on the [GTFOBins][gtfobins]-informed exploit list (`bash`,
`find`, `vim`, `gdb`, `docker`, `tar`, and similar).

A SUID-root copy of a binary that is not on that list is still a
hardening concern (it should not be SUID), but it does not produce an
escalation path.

[gtfobins]: https://gtfobins.github.io/

## Sudo command filter

For `GRANTS` edges originating from a `SUDO_RULE` node, the traversal
only proceeds if the rule's command is `ALL` or the binary is on the
sudo shell-escape list (`SUDO_SHELL_ESCAPE` in
`privmap.graph.traversal`). A rule allowing `sudo /usr/bin/foo` where
`foo` has no documented escape is not, by itself, a path to root.

## What survives

After validation, what remains is a set of paths each of which:

1. Starts at a non-privileged user with a real shell.
2. Ends at a sink (root, sudo ALL, exploitable dangerous capability).
3. Has no `CAN_WRITE` edge whose target is structurally orphaned.
4. Does not pass through an auth-required SUID, known-safe cap binary,
   or non-exploitable sudo rule.

These are the paths reported in the CLI, JSON, and markdown output and
used by [scoring](scoring.md) to assign severity.

## When validation gets it wrong

False negatives (paths that are exploitable but get filtered) are
typically caused by:

- A novel sudo binary not on the shell-escape list. Open a GitHub issue
  with the GTFOBins entry; the list is updated regularly.
- A non-standard capability binary that does expose its caps to the
  caller. By default these are not on the known-safe list; if you see
  one filtered incorrectly, it would have to be on the user-extended
  allowlist (not currently configurable in 1.x).

False positives are documented under
[known limitations](../limitations.md).
