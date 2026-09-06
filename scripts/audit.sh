#!/usr/bin/env bash
set -euo pipefail

# Run a RustSec advisory audit over the workspace dependency tree.
# Installs cargo-audit on demand so the target works in clean CI images.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$("$ROOT/scripts/tool-version.sh" cargo-audit)"

if ! cargo-audit --version 2>/dev/null | grep -qE "(^|[[:space:]])${VERSION}([[:space:]]|$)"; then
	echo "Installing cargo-audit $VERSION..."
	cargo install cargo-audit --version "$VERSION" --locked --force
fi

echo "Running security audit..."
cargo audit
