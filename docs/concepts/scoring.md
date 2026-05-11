# Scoring and severity

Every escalation path is scored on two independent axes before being
assigned a severity rating.

- **Exploitability** (0 to 10). How easy is it to actually walk this path?
- **Impact** (0 to 10). What does the attacker gain at the end of it?

The severity is derived from the combination, with the same emphasis a
CVSS scorer would apply. A 10/10 exploitability with a 2/10 impact is not
a critical finding, and vice versa.

## Severity tiers

| Severity   | Typical conditions                                                              |
|------------|---------------------------------------------------------------------------------|
| `CRITICAL` | Short path (3 hops or fewer), high exploitability, reaches root or sudo `ALL`.  |
| `HIGH`     | Reaches root, but multi-hop or has a small capability gate.                     |
| `MEDIUM`   | Reaches a non-root privileged user, or a long path to root.                     |
| `LOW`      | Reaches a sink but requires specific conditions or a long chain.                |
| `INFO`     | Structurally a sink, but largely intended behavior (e.g. admin in sudo group).  |

The exact thresholds live in `privmap.analysis.scoring`. They are stable
across patch releases but can be retuned in a minor release if data
informs us that the current thresholds are too noisy or too quiet.

## Exploitability factors

The following lower the exploitability score:

- **Path length.** Each additional hop reduces the score, since a
  multi-step chain has more opportunities to break.
- **Argument-restricted sudo rules.** `sudo systemctl restart nginx` is
  less exploitable than `sudo systemctl`. privmap recognises common
  restriction patterns; complex `sudoers` arguments (full glob and quote
  support) are best-effort.
- **Non-shell-escape sudo binaries.** `sudo /usr/bin/foo` where `foo` is
  not in the [GTFOBins shell-escape list][gtfobins] gets a much lower
  score than `sudo /usr/bin/find`.
- **Group ACLs vs direct user ACLs.** Group ACLs are emitted per member;
  the presence of multiple required hops to reach the writable resource
  lowers the score.

The following raise it:

- **`NOPASSWD:`** on a sudo rule. No credential prompt, fully scripted.
- **World-writable execution targets.** Anyone can swap the binary.
- **Capability binaries with dangerous caps.** `cap_setuid+ep` on a
  binary the user can execute is a direct privilege escalation.

[gtfobins]: https://gtfobins.github.io/

## Impact factors

Impact is governed by what the path reaches, not how it gets there:

| Sink                                                  | Impact |
|-------------------------------------------------------|--------|
| `root` (uid 0)                                        | 10     |
| Sudo `ALL` (transitively root)                        | 10     |
| Dangerous capability (transitively root)              | 9 to 10|
| Privileged service account (postgres, www-data, etc.) | 5 to 7 |
| Non-system account                                    | 2 to 4 |

privmap treats reaching root and reaching any path that trivially leads
to root as equivalent. The distinction only matters when a path stops
short of root.

## Why some "critical" findings are filtered

privmap deliberately suppresses several classes of structurally-critical
paths because they are not actually exploitable for free:

- **Auth-required SUID binaries** (`su`, `sudo`, `pkexec`, and so on).
  SUID by design and require a credential. Filtered before path emission.
- **Known-safe capability binaries** (`ping`, `mtr`, and so on). Use
  capabilities internally without exposing them.
- **World-writable files in sticky directories** (`/tmp`, `/var/tmp`).
  The sticky bit prevents non-owners from replacing or unlinking them,
  so the world-writable bit is not exploitable.
- **CAN_WRITE edges whose target is not actually executed.** A writable
  file with no inbound `EXECUTES` edge and no `RUNS_AS` or `EXECUTES`
  downstream is not part of a real chain. This is enforced by
  [path validation](path-validation.md).

See [known limitations](../limitations.md) for the inverse: findings that
may be over-reported and warrant manual review.

## Tuning

There is no `--severity-weights` flag in 1.x. If you need different
thresholds for a specific deployment, the simplest approach is to consume
`--output json` and re-score downstream based on
`paths[].exploitability` and `paths[].impact`. Both numbers are stable
parts of the JSON contract.
