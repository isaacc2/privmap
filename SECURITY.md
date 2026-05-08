# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in privmap, please report it privately rather than opening a public issue.

Use GitHub's private vulnerability reporting feature on the repository's Security tab.

You can expect an initial response within 7 days. Verified vulnerabilities will be addressed in a patch release with credit to the reporter (unless anonymity is requested).

## Scope

privmap is an analysis tool that reads system configuration. It does not execute exploits or modify system state. Reports are most relevant for:

- Code execution vulnerabilities in parsing logic
- Path traversal or arbitrary file read in snapshot extraction
- Denial of service in graph traversal
