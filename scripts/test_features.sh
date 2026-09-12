#!/usr/bin/env bash
set -euo pipefail

# Feature-matrix gate. Run with: make test-all
#
# A `cargo test` of `tightbeam-rs` pulls the self dev-dependency, and Cargo
# unifies its features into the package, so a narrow `--features` selection
# holds only for `cargo check`. A selection that must execute gets a probe
# package outside this workspace: steps 8, 10 and 14.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! "$ROOT/scripts/tool-installed.sh" cargo-hack; then
	HACK_VERSION="$("$ROOT/scripts/tool-version.sh" cargo-hack)"
	echo "Installing cargo-hack $HACK_VERSION..."
	cargo install cargo-hack --version "$HACK_VERSION" --locked --force
fi

echo "=== Feature Combination Tests ==="

echo "[1/16] Check: every feature on its own (cargo hack --each-feature)"
cargo hack check --package tightbeam-rs --each-feature --no-dev-deps \
	--exclude-features tcp,async-transport,tokio

echo "[2/16] Check: the excluded features still refuse to build alone"
for feature in tcp async-transport tokio; do
	if cargo check --package tightbeam-rs --no-default-features --features "$feature" >/dev/null 2>&1; then
		echo "  FAIL: '$feature' now builds alone. Drop it from --exclude-features in step 1." >&2
		exit 1
	fi
	echo "  ok: $feature refuses to build without a handshake protocol"
done

echo "[3/16] Check: the protocol-requiring features with a protocol"
cargo check --package tightbeam-rs --no-default-features --features "std,tcp,async-transport,tokio,transport-ecies"

echo "[4/16] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-ecies,tcp,tokio,testing"

echo "[5/16] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,derive,testing"

echo "[6/16] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

echo "[7/16] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

echo "[8/16] Test: Consumer expansion under a narrow and a wide selection"
for selection in narrow wide; do
	cargo test --manifest-path "$ROOT/consumer-expansion-test/Cargo.toml" \
		--target-dir "$ROOT/target/probe-expansion" \
		--no-default-features --features "$selection"
done

echo "[9/16] Test: Consumer macro expansions"
cargo test --package tightbeam-consumer-test

echo "[10/16] Test: Consumer on tightbeam default features"
cargo test --manifest-path "$ROOT/consumer-default-test/Cargo.toml" \
	--target-dir "$ROOT/target/probe-default"

echo "[11/16] Check: Transport CMS"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

echo "[12/16] Check: Transport ECIES"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-ecies,testing"

echo "[13/16] Check: Transport CMS-only + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,tcp,tokio,testing"

echo "[14/16] Test: Sync server stack (std + tcp + ECIES, no tokio)"
cargo test --manifest-path "$ROOT/consumer-sync-test/Cargo.toml" \
	--target-dir "$ROOT/target/probe-sync"

echo "[15/16] Test: Crate defaults plus the dev feature set"
cargo test --package tightbeam-rs

echo "[16/16] Test: Workspace all features"
cargo test --workspace --all-features

# wasm32 browser transport core: async-transport compiles the generic
# AsyncProtocolStream + TcpTransport without tokio.
echo "[wasm] Check: wasm32 transport-ecies + async-transport (no tokio)"
if rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
	cargo check --target wasm32-unknown-unknown --package tightbeam-rs --no-default-features --features "std,transport-ecies,async-transport,wasm"
else
	echo "  FAIL: wasm32-unknown-unknown target missing (run: make setup)" >&2
	exit 1
fi

echo "=== All feature tests passed ==="
