#!/usr/bin/env bash
set -euo pipefail

# Check the dependency tree against deny.toml: RustSec advisories, the licence
# allow-list, banned and wildcard dependencies, and the permitted sources.
# Installs cargo-deny on demand so the target works in clean CI images.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! "$ROOT/scripts/tool-installed.sh" cargo-deny; then
	VERSION="$("$ROOT/scripts/tool-version.sh" cargo-deny)"
	echo "Installing cargo-deny $VERSION..."
	cargo install cargo-deny --version "$VERSION" --locked --force
fi

echo "Running dependency audit..."
cargo deny --manifest-path "$ROOT/Cargo.toml" check
