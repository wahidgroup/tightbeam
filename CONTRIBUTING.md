# Contributing

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Getting Started

Contributors MUST have the Rust toolchain (via [rustup](https://rustup.rs); see `rust-toolchain.toml`), Git, and Make.

```bash
make setup
make lint
make ci
```

Use `make help` for the full command list. Apply fixes with `make lint fix=1`.

Git hooks live in `.husky/` and are installed automatically by [husky-rs](https://crates.io/crates/husky-rs) (which sets `core.hooksPath`) the first time `cargo test` builds dev-dependencies. Set `NO_HUSKY_HOOKS=1` to skip installation (CI does this).

- `commit-msg` - enforces the commit header format (see [Title](#title))
- `pre-push` - runs `make lint` and verifies commit signatures. Commits MUST be signed before push.

### Code Style

Contributors MUST:

- Use hard tabs everywhere except YAML (2 spaces), enforced by EditorConfig
- Pass `make lint` (and preferably `make ci`) before opening a PR
- Rust: no `unwrap` / `expect` / `panic` in production code; enum error types, no string-based errors; prefer `From` / `TryFrom` and `?`
- Keep test-support Rust code behind the `testing` cargo feature; it MUST NOT compile into a default build

### Useful targets

```bash
make test                              # cargo test
make test-all                          # feature-matrix script
make build features="std,tcp,tokio"    # feature-gated build
make test no-default=1 features="testing"
make fuzz-test                         # short AFL smoke run
make doc                               # cargo doc --all-features
make release version=v0.9.1            # see make help
```

## Pull Requests

All pull requests MUST conform to the title, body, and metadata specifications below. The `PR Checks` workflow (`Title`, `Body`, `Metadata` jobs) blocks merge on non-compliance.

### Title

PR titles and commit headers MUST follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope][!]: <description>
```

#### Type

The type MUST be lowercase and one of:

| Type       | Purpose                                                 | Semver |
| ---------- | ------------------------------------------------------- | ------ |
| `feat`     | New feature                                             | MINOR  |
| `fix`      | Bug fix                                                 | PATCH  |
| `docs`     | Documentation only                                      | -      |
| `style`    | Formatting, whitespace, no logic change                 | -      |
| `refactor` | Code change that neither fixes a bug nor adds a feature | -      |
| `perf`     | Performance improvement                                 | PATCH  |
| `test`     | Adding or correcting tests                              | -      |
| `build`    | Build system or dependency changes                      | -      |
| `ci`       | CI configuration changes                                | -      |
| `chore`    | Maintenance, no production code change                  | -      |
| `revert`   | Revert a previous commit                                | -      |

#### Scope

The scope is OPTIONAL, MUST be lowercase (`[a-z0-9/-]+`), and identifies the affected area. Recommended scopes:

- Crate: `tightbeam`, `tightbeam-derive`
- Layer: `transport`, `crypto`, `colony`, `builder`, `asn1`, `docs`
- Cross-cutting: `deps`, `ci`, `scripts`

#### Description

The description MUST:

- Use imperative mood ("add" not "added" / "adds")
- Start with a lowercase letter or digit (not Sentence case)
- NOT end with a period
- Keep the full header under 100 characters

#### Breaking Changes

Append `!` after the type or scope to indicate a breaking change:

```
feat!: drop support for the legacy handshake
refactor(transport)!: rename handshake processor trait
```

### Body

The PR body MUST contain these five sections, each with non-empty content:

| Section               | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `## Summary`          | WHY this change exists and WHAT it accomplishes                         |
| `## Related Issues`   | Issue links (`Fixes #N`, `Closes #N`, `Refs #N`, or `None`)             |
| `## Changes Made`     | Bullet list of user/system-visible changes                              |
| `## Testing`          | How a reviewer verifies the change (commands, steps, expected outcomes) |
| `## Breaking Changes` | Migration path for consumers, or `None`                                 |

The PR template at `.github/PULL_REQUEST_TEMPLATE.md` auto-populates these sections. Release PRs (head branch `process/v*`) are exempt from body validation.

Testing section SHOULD cite `make ci` (or the relevant `make` targets) when behavior changes.

### Metadata

Each PR MUST have:

- At least one **assignee** (the person responsible for landing the PR)
- At least one **label** (for categorization and triage)

## Types of Contributions

### Bug Reports

When reporting bugs, you MUST include:

- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Rust version, features used)
- Minimal test case if possible

### Feature Requests

For new features, contributors MUST:

1. Check if a TIP (tightbeam improvement proposal) is needed
2. Discuss the feature in an issue first
3. Consider backwards compatibility
4. Provide use cases and rationale
5. Utilize RustCrypto crates for cryptographic implementations

### Documentation

Contributors MUST:

- Update relevant documentation for any changes
- Ensure examples compile and work correctly
- Update ASN.1 specifications for protocol changes

### Security

For security-related contributions, contributors MUST follow [SECURITY.md](SECURITY.md) (private advisory disclosure).

## Releasing

The workspace is versioned from `[workspace.package]` in `Cargo.toml`. Maintainers release with:

```bash
make release version=vX.Y.Z
```

Use `dry-run=1`, `allow-staged=1`, or `yank=1` as documented in `make help`.

A release bumps the workspace version, opens a release pull request, and on merge creates a signed `releases/v*` tag that publishes to crates.io (`tightbeam-derive` is published first when its version is ahead of crates.io). Bump `tightbeam-derive`'s own package version in the same PR when the derive crate itself changes. The deploy guard `check-yanked.sh` refuses yanked versions.

## tightbeam Improvement Proposals (TIPs)

For significant changes, contributors MUST follow the TIP process:

1. Read [TIP-1](tips/tip-0001.md) for guidelines
2. Draft your TIP in `tips/` directory
3. Submit as a pull request for discussion
4. Build consensus through community feedback

## License

By contributing, you agree that your contributions will be licensed under the
same dual MIT/Apache-2.0 license as the project.
