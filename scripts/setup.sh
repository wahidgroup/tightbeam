#!/usr/bin/env bash
set -euo pipefail

# Idempotent development-environment setup: Rust toolchain components,
# cargo-audit, and typos. A content hash of the manifests is stamped under
# .make/ so unchanged re-runs are skipped.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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
			2>/dev/null
	} | "${SHA256_CMD[@]}" | awk '{ print $1 }'
}

setup_required() {
	if ! command -v cargo-audit >/dev/null 2>&1; then
		return 0
	fi
	if ! command -v typos >/dev/null 2>&1; then
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

	if ! command -v cargo-audit >/dev/null 2>&1; then
		echo "Installing cargo-audit..."
		cargo install cargo-audit --locked
	fi
	if ! command -v typos >/dev/null 2>&1; then
		echo "Installing typos..."
		cargo install typos-cli --locked
	fi
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
