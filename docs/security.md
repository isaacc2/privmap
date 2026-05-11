# Security policy

The authoritative copy of the security policy lives at
[`SECURITY.md`](https://github.com/isaacc2/privmap/blob/main/SECURITY.md)
in the repository. This page mirrors it for the docs site.

## Reporting a vulnerability

If you discover a security vulnerability in privmap, please report it
privately rather than opening a public issue. Use GitHub's [private
vulnerability reporting](https://github.com/isaacc2/privmap/security/advisories/new)
on the repository's Security tab, or email the maintainer directly.

You can expect an initial response within 7 days. Verified vulnerabilities
will be addressed in a patch release with credit to the reporter unless
anonymity is requested.

## In scope

privmap is an analysis tool that reads system configuration. It does not
execute exploits or modify system state. Reports are most relevant for:

- Code execution vulnerabilities in parsing logic.
- Path traversal or arbitrary file read in snapshot extraction.
- Denial of service in graph traversal.
- Logic errors that cause privmap to systematically under- or over-report.

## Out of scope

- Bugs that cause partial scan results when running without root. By design,
  privmap is allowed to skip privileged inputs and warn.
- Findings that privmap *fails to detect* because the underlying system
  configuration is unusual or the analysis is best-effort. See
  [known limitations](limitations.md).
- Issues in third-party tools privmap invokes (`getcap`, `getfacl`).
