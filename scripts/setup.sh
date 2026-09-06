#!/usr/bin/env bash
set -euo pipefail

# Idempotent development-environment setup: Rust toolchain components,
# cargo-audit, typos, and cargo-afl. A content hash of the manifests is
# stamped under .make/ so unchanged re-runs are skipped.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL_VERSION="$ROOT/scripts/tool-version.sh"
STAMP_DIR="$ROOT/.make"
SETUP_HASH_FILE="$STAMP_DIR/setup.hash"
LOCK_FILE="$STAMP_DIR/setup.lock"
LOCK_DIR="$STAMP_DIR/setup.lock.d"
LOCK_FD=9
LOCK_KIND=""

# sha256sum (Linux) or shasum (macOS); both print "hash  path".
if command -v sha256sum >/dev/null 2>&1; then
	SHA256_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
	SHA256_CMD=(shasum -a 256)
else
	echo "ERROR: setup needs sha256sum or shasum on PATH." >&2
	exit 1
fi

compute_setup_hash() {
	{
		"${SHA256_CMD[@]}" \
			"$ROOT/Cargo.toml" \
			"$ROOT/Cargo.lock" \
			"$ROOT/rust-toolchain.toml" \
			"$ROOT/typos.toml" \
			"$ROOT/scripts/setup.sh" \
			"$ROOT/scripts/tool-version.sh" \
			2>/dev/null
	} | "${SHA256_CMD[@]}" | awk '{ print $1 }'
}

pinned() {
	"$TOOL_VERSION" "$1"
}

tool_at_version() {
	local binary="$1"
	local version="$2"
	local probe=(--version)

	command -v "$binary" >/dev/null 2>&1 || return 1

	if [ "$binary" = "cargo-afl" ]; then
		probe=(afl --version)
	fi

	"$binary" "${probe[@]}" 2>/dev/null | grep -qE "(^|[[:space:]])${version}([[:space:]]|\$)"
}

install_pinned() {
	local binary="$1"
	local crate="$2"
	local version="$3"

	if tool_at_version "$binary" "$version"; then
		return 0
	fi

	echo "Installing $crate $version..."
	cargo install "$crate" --version "$version" --locked --force
}

setup_required() {
	if ! tool_at_version cargo-audit "$(pinned cargo-audit)"; then
		return 0
	fi
	if ! tool_at_version typos "$(pinned typos-cli)"; then
		return 0
	fi
	if ! tool_at_version cargo-afl "$(pinned cargo-afl)"; then
		return 0
	fi
	if [ ! -f "$SETUP_HASH_FILE" ]; then
		return 0
	fi

	local current_hash
	local saved_hash=""
	current_hash="$(compute_setup_hash)"
	saved_hash="$(tr -d '\n' < "$SETUP_HASH_FILE")"
	if [ "$current_hash" != "$saved_hash" ]; then
		return 0
	fi

	return 1
}

release_lock() {
	if [ "$LOCK_KIND" = "flock" ]; then
		flock -u "$LOCK_FD" 2>/dev/null || true
		eval "exec ${LOCK_FD}>&-"
	elif [ "$LOCK_KIND" = "mkdir" ]; then
		rmdir "$LOCK_DIR" 2>/dev/null || true
	fi
	LOCK_KIND=""
}

acquire_lock() {
	# Serialize installs across parallel make jobs / concurrent setup.sh.
	if command -v flock >/dev/null 2>&1; then
		eval "exec ${LOCK_FD}>\"\$LOCK_FILE\""
		if ! flock -w 600 "$LOCK_FD"; then
			echo "ERROR: timed out waiting for setup lock (${LOCK_FILE})." >&2
			exit 1
		fi
		LOCK_KIND="flock"
		return
	fi

	local waited=0
	while ! mkdir "$LOCK_DIR" 2>/dev/null; do
		if [ "$waited" -ge 600 ]; then
			echo "ERROR: timed out waiting for setup lock (${LOCK_DIR})." >&2
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
	LOCK_KIND="mkdir"
}

install_rust_tooling() {
	echo "Installing pinned toolchain, components, and targets (rust-toolchain.toml)..."
	rustup toolchain install
	rustup component add rustfmt clippy

	install_pinned cargo-audit cargo-audit "$(pinned cargo-audit)"
	install_pinned typos typos-cli "$(pinned typos-cli)"
	install_pinned cargo-afl cargo-afl "$(pinned cargo-afl)"
}

main() {
	mkdir -p "$STAMP_DIR"
	acquire_lock
	trap release_lock EXIT

	# Re-check under lock: a waiter may find the stamp already written.
	if setup_required; then
		install_rust_tooling

		compute_setup_hash > "$SETUP_HASH_FILE"
		echo "Setup complete."
	else
		echo "Setup already up to date."
	fi
}

main "$@"
