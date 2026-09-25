# Consumer probes

Each crate here depends on `tightbeam-rs` the way a downstream user would: over a `path` dependency, with one explicit feature selection. They exist to catch what an in-crate test cannot, because an in-crate test compiles against whatever feature set the test run happens to enable.

They are separate crates rather than one crate with four test files because Cargo unifies features across a dependency graph. Two selections of `tightbeam-rs` in one crate collapse into their union, and the union is not what any of these probes assert.

| Crate | Selection | Asserts |
| --- | --- | --- |
| `full` | Workspace member; the broad selection, including `testing` and `testing-csp` | Macro expansions compile, and the public error enums stay sealed against exhaustive `match` |
| `default` | `tightbeam-rs` default features | The verification harness is unreachable: `tightbeam::testing` does not resolve |
| `expansion` | `narrow` and `wide`, two selections of the same body | One `tb_scenario!` body compiles under both |
| `sync` | `std`, `tcp`, `transport-ecies`, no `tokio` | The server stack builds and runs without an async runtime |

`default`, `expansion` and `sync` are listed under `exclude` in the root `Cargo.toml`, so each resolves its own dependency graph and carries its own `Cargo.lock`. Only `full` is a workspace member, since its selection is a superset of the workspace's own.

`scripts/test_features.sh` runs all four. The excluded three build into their own directories under `target/` so they do not invalidate the workspace's build cache.
