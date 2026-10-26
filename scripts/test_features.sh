#!/usr/bin/env bash
set -euo pipefail

# Feature-matrix gate. Run with: make test-all
#
# A `cargo test` of `tightbeam-rs` pulls the self dev-dependency, and Cargo
# unifies its features into the package, so a narrow `--features` selection
# holds only for `cargo check`. A selection that must execute gets a probe
# package outside this workspace: steps 8, 10 and 14.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# `cargo hack --no-dev-deps` strips `[dev-dependencies]` out of every
# workspace manifest in place and puts them back when it finishes. A run
# that dies first, including one a person interrupts, leaves them stripped,
# and the next build fails on a missing dev-only crate.
MANIFEST_SNAPSHOT="$(mktemp -d)"

# Runs from the EXIT trap, and from the signal traps before they exit.
restore_manifests() {
	local relative

	[ -d "$MANIFEST_SNAPSHOT" ] || return 0

	for relative in "${TRACKED_MANIFESTS[@]}"; do
		if ! cmp -s "$MANIFEST_SNAPSHOT/$relative" "$ROOT/$relative"; then
			cp "$MANIFEST_SNAPSHOT/$relative" "$ROOT/$relative"
			echo "  restored $relative (a stripped manifest was left behind)" >&2
		fi
	done

	rm -rf "$MANIFEST_SNAPSHOT"
}

# A signal handler that returns lets the run carry on into the next step,
# so each one restores and then leaves with the conventional code.
on_signal() {
	local signal_code="$1"

	restore_manifests
	exit "$signal_code"
}

mapfile -t TRACKED_MANIFESTS < <(cd "$ROOT" && git ls-files '*Cargo.toml')
for manifest in "${TRACKED_MANIFESTS[@]}"; do
	mkdir -p "$MANIFEST_SNAPSHOT/$(dirname "$manifest")"
	cp "$ROOT/$manifest" "$MANIFEST_SNAPSHOT/$manifest"
done

trap restore_manifests EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

if ! "$ROOT/scripts/tool-installed.sh" cargo-hack; then
	HACK_VERSION="$("$ROOT/scripts/tool-version.sh" cargo-hack)"
	echo "Installing cargo-hack $HACK_VERSION..."
	cargo install cargo-hack --version "$HACK_VERSION" --locked --force
fi

echo "=== Feature Combination Tests ==="

echo "[1/18] Check: every feature on its own (cargo hack --each-feature)"
cargo hack check --package tightbeam-rs --each-feature --no-dev-deps \
	--exclude-features tcp,async-transport,tokio

echo "[2/18] Check: the excluded features still refuse to build alone"
for feature in tcp async-transport tokio; do
	if cargo check --package tightbeam-rs --no-default-features --features "$feature" >/dev/null 2>&1; then
		echo "  FAIL: '$feature' now builds alone. Drop it from --exclude-features in step 1." >&2
		exit 1
	fi
	echo "  ok: $feature refuses to build without a handshake protocol"
done

echo "[3/18] Check: the protocol-requiring features with a protocol"
cargo check --package tightbeam-rs --no-default-features --features "std,tcp,async-transport,tokio,transport-hpke"

echo "[4/18] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-hpke,tcp,tokio,testing"

echo "[5/18] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

echo "[6/18] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

echo "[7/18] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

echo "[8/18] Test: Consumer expansion under a narrow and a wide selection"
for selection in narrow wide; do
	cargo test --manifest-path "$ROOT/consumers/expansion/Cargo.toml" \
		--target-dir "$ROOT/target/probe-expansion" \
		--no-default-features --features "$selection"
done

echo "[9/18] Test: Consumer macro expansions"
cargo test --package tightbeam-consumer-test

echo "[10/18] Test: Consumer on tightbeam default features"
cargo test --manifest-path "$ROOT/consumers/default/Cargo.toml" \
	--target-dir "$ROOT/target/probe-default"

echo "[11/18] Check: Transport CMS"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

echo "[12/18] Check: Transport HPKE"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-hpke,testing"

echo "[13/18] Check: Transport CMS-only + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,tcp,tokio,testing"

echo "[14/18] Test: Sync server stack (std + tcp + HPKE, no tokio)"
cargo test --manifest-path "$ROOT/consumers/sync/Cargo.toml" \
	--target-dir "$ROOT/target/probe-sync"

# The dev feature set leaves `rayon` off, so this step runs the suite on the
# sequential FDR walk and step 16 runs it on the parallel one. A dev feature
# that turns `rayon` on fails the step before the run.
echo "[15/18] Test: Crate defaults plus the dev feature set, without rayon"
# A tree with no `rayon` in it exits non-zero, which reads as the empty tree.
RAYON_TREE="$(cargo tree --package tightbeam-rs --edges features --invert rayon 2>/dev/null || true)"
if grep -q 'feature "rayon"' <<<"$RAYON_TREE"; then
	echo "  FAIL: the dev feature set turns on rayon, so no step runs the suite without it." >&2
	exit 1
fi
cargo test --package tightbeam-rs

echo "[16/18] Test: Workspace all features"
cargo test --workspace --all-features

# The KEM recipients build under `hpke` and `signature`, and DHKEM needs the
# ECDH of the `ecdh` feature, which `hpke` enables.
echo "[17/18] Check: KEM recipients (hpke + signature)"
cargo check --package tightbeam-rs --no-default-features --features "hpke,signature"

# Only a build with an async runtime runs the mux driver, so the rekey and each
# part that only the rekey calls take the gate of their callers, the
# `mux_rekey` alias of `tightbeam/build.rs`. The check denies warnings, so an
# item that outlives its last caller fails the build here. The last selection
# builds the rekey with one handshake protocol.
echo "[18/18] Check: multiplexing with and without the mux rekey, warnings denied"
for selection in "std,transport-cms,transport-multiplex" "transport-hpke,transport-multiplex" \
	"transport-cms,transport-multiplex" "transport-cms,transport-multiplex,async-transport"; do
	cargo rustc --package tightbeam-rs --lib --profile check --no-default-features --features "$selection" \
		-- -D warnings
done

# wasm32 browser transport core: async-transport compiles the generic
# AsyncProtocolStream + TcpTransport without tokio.
echo "[wasm] Check: wasm32 transport-hpke + async-transport (no tokio)"
if rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
	cargo check --target wasm32-unknown-unknown --package tightbeam-rs --no-default-features --features "std,transport-hpke,async-transport,wasm"
else
	echo "  FAIL: wasm32-unknown-unknown target missing (run: make setup)" >&2
	exit 1
fi

echo "=== All feature tests passed ==="
