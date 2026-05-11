# Snapshot mode

Snapshot mode separates collection from analysis. You run a POSIX shell
script on the target system, transfer the resulting tarball to your
analyst workstation, and run privmap there. The target host needs no
Python and no network egress.

This is the standard workflow for:

- Incident response on a host you cannot install software on.
- Forensic analysis after the fact.
- Air-gapped or production systems where running an arbitrary Python tool
  is out of policy.
- Bulk analysis of many hosts from a central workstation.

## Collecting on the target

The collector is shipped as `collect.sh` in the repository. It is a
single shell script, POSIX-compliant, with no dependencies beyond
standard userland utilities (`getcap`, `getfacl`, `find`, `awk`).

```bash
# On the target system:
sudo ./collect.sh
```

This produces `privmap_snapshot_<hostname>_<YYYYMMDD>.tar.gz` in the
working directory. The script collects:

- `/etc/passwd`, `/etc/group`, `/etc/shadow` (if readable),
  `/etc/sudoers`, `/etc/sudoers.d/*`
- SUID/SGID binaries, world-writable files and directories, symlink
  targets, and a recursive permission dump of `/etc`, `/usr`, `/opt`,
  `/tmp`, `/var`
- Linux capability binaries (`getcap -r /`)
- POSIX ACLs (`getfacl -R`) on the same scan paths
- Cron: `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`,
  `/var/spool/cron/crontabs`, `/etc/crontab`
- Systemd units from the standard search paths
- `/etc/init.d` scripts
- Running process metadata from `/proc/*/status` and `/proc/*/cmdline`

Transfer the archive over whatever channel is appropriate (scp, removable
media, and so on).

## Analyzing on the workstation

```bash
privmap --snapshot ./privmap_snapshot_target_20260507.tar.gz
```

privmap will:

1. Extract the archive into a temporary directory with strict safety
   checks. See [security note](#security-note-on-extraction) below.
2. Run all ingesters against the extracted tree.
3. Report paths to stdout.
4. Clean up the temporary directory on exit.

All the live-mode flags work in snapshot mode:

```bash
privmap --snapshot snap.tar.gz --user www-data
privmap --snapshot snap.tar.gz --output json > report.json
privmap --snapshot snap.tar.gz --min-severity high
```

## Live vs snapshot

| Aspect                       | Live mode                                | Snapshot mode                                   |
|------------------------------|------------------------------------------|-------------------------------------------------|
| Filesystem walk              | `os.walk` over scan paths                | Parses `suid/permissions.txt` from archive      |
| Capabilities                 | `getcap -r <root>`                       | Reads `caps/file_capabilities.txt`              |
| ACLs                         | `getfacl -R` (live subprocess)           | Reads `acl/acls.txt`                            |
| Processes                    | `/proc/*/status` (live)                  | Reads captured `/proc` snapshot if present      |
| Permission-aware CAN_EXEC    | Real `stat()` on each binary             | Lookup in captured permissions table            |
| Cron user crontabs           | `/var/spool/cron/crontabs/*`             | `cron/user_crontabs/*` in archive               |

The analysis is otherwise identical. Same graph model, same DFS, same
scoring. Snapshot mode is conservative: where data was not captured, the
relevant edge is not emitted, never fabricated.

## Security note on extraction

privmap defends against malicious or malformed archives during
extraction. The archive is rejected with an error before any analysis
runs if it contains:

- Absolute paths (e.g. `/etc/passwd`)
- Parent-directory traversal (e.g. `../../some/file`)
- Symbolic or hard links whose targets escape the temporary directory
- Special files (device nodes, FIFOs)
- More than 200,000 members
- More than 2 GiB of uncompressed content

These limits accommodate a whole-system snapshot from a real server while
refusing tar bombs and CVE-2007-4559 escapes. The implementation lives in
`privmap.cli._safe_extract_tar`.

## Sharing snapshots safely

A snapshot is a complete inventory of a system's permission layout. Treat
it like a backup of `/etc`:

- `etc/shadow` contains password hashes if the collector ran as root.
  Strip it before sharing snapshots externally.
- `etc/sudoers` and `etc/sudoers.d/*` reveal trust relationships.
- `proc/*/cmdline` may contain secrets if applications pass them on the
  command line.

The collector does not collect kernel keyring entries, TLS private keys,
SSH host or user keys, or application data. It collects what privilege
analysis legitimately needs.
