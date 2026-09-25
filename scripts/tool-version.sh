#!/usr/bin/env bash
set -euo pipefail

# Read the developer-tool pins from [workspace.metadata.tools], the only home
# for which tools this repository installs and at which version.
#
#   tool-version.sh <crate-name>   print that crate's pinned version
#   tool-version.sh --list         print every pinned crate name

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

metadata() {
	cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml"
}

if [ "$#" -ne 1 ]; then
	echo "usage: $(basename "$0") <crate-name> | --list" >&2
	exit 2
fi

if [ "$1" = "--list" ]; then
	metadata | jq -r '.metadata.tools | keys[]'
	exit 0
fi

CRATE="$1"

VERSION="$(metadata | jq -r --arg crate "$CRATE" '.metadata.tools[$crate] // empty')"

if [ -z "$VERSION" ]; then
	echo "ERROR: $CRATE has no pin under [workspace.metadata.tools]." >&2
	exit 1
fi

printf '%s\n' "$VERSION"
