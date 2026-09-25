# Security Policy

## Supported Versions

Only the latest published release of `tightbeam-rs` / `tightbeam-derive` receives security updates.

| Version        | Supported          |
| -------------- | ------------------ |
| Latest release | :white_check_mark: |
| Older releases | :x:                |

## Reporting a Vulnerability

Report security issues **privately** via GitHub Security Advisories:

https://github.com/wahidgroup/tightbeam/security/advisories/new

Do **not** open a public GitHub issue, pull request, or discussion for security reports.

Include as much of the following as possible:

- Description of the issue and its potential impact
- Affected crate version(s)
- Steps to reproduce
- Suggested fix or mitigation (if known)

## Response

We aim to acknowledge reports within **5 business days**. Confirmed issues are handled under coordinated disclosure: please give reasonable time for a fix and advisory before public discussion.

Reporters are credited in the advisory and release notes unless they prefer anonymity.

## Accepted advisories

`deny.toml` ignores these RustSec advisories.

- `RUSTSEC-2023-0071`, accepted 2026-06-02: the `rsa` Marvin Attack timing side-channel has no fixed release. `cms` 0.2.3 pulls in `rsa` through its `builder` feature for the RSA KeyTrans recipient path. tightbeam uses only KARI/ECDH key agreement, so that code path never runs.
- `RUSTSEC-2024-0436`, accepted 2026-06-02: `paste` is archived because it is complete. The advisory claims no vulnerability, and no replacement is required.

## Out of Scope

- Vulnerabilities that exist only in consumer application code or misconfiguration
- Issues that require an already-compromised runtime or hostile local environment
- Reports against unsupported / unpublished versions
