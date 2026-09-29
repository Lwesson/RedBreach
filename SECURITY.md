# Security Policy

## Supported versions

Security fixes are applied to the latest released version.

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## Reporting a vulnerability

Please report security issues in RedBreach itself privately, not in public issues.

Use GitHub's private vulnerability reporting on this repository: open the
[Security tab](https://github.com/Lwesson/RedBreach/security) and choose
"Report a vulnerability", or go directly to
[github.com/Lwesson/RedBreach/security/advisories/new](https://github.com/Lwesson/RedBreach/security/advisories/new).

Please include:

- The affected version or commit
- Steps to reproduce
- The impact, and a proof of concept if you have one

We aim to acknowledge reports within 7 days and to share a fix or mitigation
timeline after triage. Please give us reasonable time to release a fix before
any public disclosure.

## Scope

This policy covers vulnerabilities in RedBreach's own code, for example unsafe
handling of credentials or evidence, injection in how it invokes external tools,
or a flaw that causes it to act outside a configured scope.

It does not cover findings you produced by running RedBreach against a
third-party target. Those belong to that target's own disclosure program. See
the "Authorized use only" section of the [README](README.md) for how this tool
is meant to be used.
