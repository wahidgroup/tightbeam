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

## Accepted risks

These risks carry no RustSec advisory.

- `ml-kem` 0.2.3, accepted 2026-10-29, under the `preview-pqc` feature: its noise sampler reads a table at an index that secret values choose, in key generation, encapsulation, and decapsulation, which is a timing side channel. `ml-kem` 0.3.3 replaces the lookup with arithmetic (RustCrypto/KEMs #386), and it needs the `rand_core` 0.10 and `sha3` 0.12 line that the stable releases this crate depends on still precede. The house runs ML-KEM-768 and ML-KEM-1024 alone, whose table holds 16 entries of 2 octets.

## Out of Scope

- Vulnerabilities that exist only in consumer application code or misconfiguration
- Issues that require an already-compromised runtime or hostile local environment
- Reports against unsupported / unpublished versions
