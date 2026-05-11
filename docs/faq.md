# FAQ

## How does privmap differ from LinPEAS, LinEnum, BeRoot?

Those tools enumerate privilege-relevant findings as flat lists of
independent observations. privmap connects them. Every finding is a node
or edge in one graph, and the report is the set of concrete chains from
each non-privileged user to a high-value sink.

If you already use LinPEAS, run privmap in addition. They answer
different questions. LinPEAS says "here is everything that looks
suspicious"; privmap says "here is the specific sequence of
misconfigurations that lets www-data become root, in this order, via
this writable file."

## Do I need to run it as root?

For useful results, yes. Without root privmap cannot read `/etc/shadow`,
walk every directory under `/etc`, enumerate other users' processes, or
list `/var/spool/cron/crontabs`. It will still run unprivileged but will
log warnings for each privileged source it could not read, and the
report will be incomplete.

Snapshot mode separates the privileged collection step (which needs
root on the target) from the analysis step (which does not need root on
the analyst workstation).

## Why is pkexec, su, or sudo not flagged as a CRITICAL path?

Because they require authentication. `su`, `pkexec`, `sudo`, `doas`,
and similar SUID binaries are SUID by design and gate access behind a
credential prompt. Their existence on a system is not, by itself, an
escalation path. Flagging them produces a critical-severity finding
for every user on every Linux system, which is noise.

If you need version-based CVE detection against these binaries
(PwnKit, Baron Samedit, and similar), pair privmap with a vulnerability
scanner. privmap does not do version matching.

## Why is some `/tmp/*` file not flagged as world-writable?

The sticky bit on the parent directory (`/tmp` is `1777`) prevents
non-owners from replacing or unlinking files inside it. The
world-writable mode bit on a file in a sticky directory is not
exploitable, so privmap suppresses the `CAN_WRITE` edge.

If you have a file in a sticky directory whose contents the owner
expects will be appended to (a log file, for instance), and a
privileged process reads that file, the relevant relationship is the
write *to that file by the owner*, not the world-writability bit. That
is not currently modeled.

## Can privmap analyze a remote host?

Yes, via [snapshot mode](usage/snapshot-mode.md). Run `collect.sh` on
the target, transfer the resulting tarball over whatever channel is
appropriate (scp, removable media, S3, and similar), and run privmap
against it on your workstation.

There is no native SSH mode and no plan to add one. That would put
privmap in the network-egress business, which doubles its threat
surface without adding capability you cannot get from
`ssh + scp + privmap --snapshot`.

## Can I get a SARIF report for GitHub code-scanning?

Not in 1.x. The JSON format (`--output json`) is the supported
structured output today. A SARIF formatter is a reasonable feature
request. File an issue if you would use it.

## Can I get a Neo4j, Cypher, or BloodHound-style query interface?

Not as a built-in feature. You can export the full graph with
`--export-graph graph.json` or `to_networkx()` (see
[Python API](reference/python-api.md)) and feed it into Neo4j, Gephi,
or any tool that consumes a graph format.

## How long does a scan take?

On a typical Debian server with ~80k files in the default scan
paths, ~50 users, ~200 SUID binaries, and ~300 systemd units: 30
to 90 seconds. The filesystem walk dominates. Snapshot mode is faster
because there are no live subprocesses for `getcap` and `getfacl`.

Narrow `--scan-paths` for faster runs in CI:

```bash
privmap --scan-paths /etc,/usr/local,/opt
```

## Can I extend the known-safe allowlists?

Yes, by editing `AUTH_REQUIRED_SUID` (in `privmap.graph.traversal`) or
`KNOWN_SAFE_CAP_BINARIES` (in `privmap.ingestion.capabilities`) and
reinstalling. A configurable allowlist via CLI flag or config file is
on the roadmap. If you have a binary that should be on the default
list, open a PR.

## How is severity calculated?

See [Scoring and severity](concepts/scoring.md). Each path is scored on
exploitability (0 to 10) and impact (0 to 10) independently, and the
severity tier is derived from the combination.

## What does "writable file with no executor" mean?

It means privmap found a file you can write to, but nothing privileged
runs it. That writability is not part of an escalation chain on its
own, so it is not reported. If you think it should be (a real executor
that privmap missed), that is a bug. File an issue with the path and
how it is invoked.

See [path validation](concepts/path-validation.md) for the full filter.

## Is privmap safe to run on production?

Yes. privmap is a read-only tool. It makes no writes to the target
system, exposes no listening sockets, and does not execute or modify
any program it finds. The longest operations (`getcap -r /`,
`getfacl -R`, the filesystem walk) are bounded by hardcoded timeouts.

A comprehensive filesystem walk on a busy server is I/O. Schedule it
like any other audit job, not in the middle of a peak hour.

## How do I report a security issue in privmap itself?

See the [Security policy](security.md).
