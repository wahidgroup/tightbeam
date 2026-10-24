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

- `RUSTSEC-2024-0436`, accepted 2026-06-02: `paste` is archived because it is complete. The advisory claims no vulnerability, and no replacement is required.
- `RUSTSEC-2026-0387`, accepted 2026-10-23: `crypto-bigint` 0.5.5 has timing variability in operations meant to run in constant time. The fixed release needs the RustCrypto line built on `der` 0.8, and the stable releases this crate depends on, `cms` among them, still use `der` 0.7. Of the four affected operation classes, only subtraction runs on secret values here, in ECDSA signing, ECDH, and key generation.

## Out of Scope

- Vulnerabilities that exist only in consumer application code or misconfiguration
- Issues that require an already-compromised runtime or hostile local environment
- Reports against unsupported / unpublished versions
