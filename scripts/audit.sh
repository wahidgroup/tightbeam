#!/usr/bin/env bash
set -euo pipefail

# Run a RustSec advisory audit over the workspace dependency tree.
# Installs cargo-audit on demand so the target works in clean CI images.

if ! command -v cargo-audit >/dev/null 2>&1; then
	echo "Installing cargo-audit..."
	cargo install cargo-audit --locked
fi

echo "Running security audit..."
cargo audit
