#!/usr/bin/env bash
set -euo pipefail

# Print the version cargo resolves for a workspace package:
#   crate-version.sh tightbeam-rs
#
# Cargo is the single home for this fact. Hand-parsing Cargo.toml misses
# workspace inheritance and drifts from what `cargo publish` would send.

if [ "$#" -ne 1 ]; then
	echo "usage: $(basename "$0") <package-name>" >&2
	exit 2
fi

PACKAGE="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VERSION="$(
	cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" |
		jq -r --arg package "$PACKAGE" '.packages[] | select(.name == $package) | .version'
)"

if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
	echo "ERROR: $PACKAGE is not a member of this workspace." >&2
	exit 1
fi

printf '%s\n' "$VERSION"
