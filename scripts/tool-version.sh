#!/usr/bin/env bash
set -euo pipefail

# Print the pinned version of a developer tool: tool-version.sh <crate-name>

if [ "$#" -ne 1 ]; then
	echo "usage: $(basename "$0") <crate-name>" >&2
	exit 2
fi

CRATE="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VERSION="$(
	cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" |
		jq -r --arg crate "$CRATE" '.metadata.tools[$crate] // empty'
)"

if [ -z "$VERSION" ]; then
	echo "ERROR: $CRATE has no pin under [workspace.metadata.tools]." >&2
	exit 1
fi

printf '%s\n' "$VERSION"
