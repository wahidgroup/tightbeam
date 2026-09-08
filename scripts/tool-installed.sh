#!/usr/bin/env bash
set -euo pipefail

# Exit 0 when a pinned developer tool is installed at its pinned version:
#   tool-installed.sh <crate-name>

if [ "$#" -ne 1 ]; then
	echo "usage: $(basename "$0") <crate-name>" >&2
	exit 2
fi

CRATE="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$("$ROOT/scripts/tool-version.sh" "$CRATE")"

case "$CRATE" in
	cargo-*) PROBE=(cargo "${CRATE#cargo-}" --version) ;;
	*) PROBE=("${CRATE%-cli}" --version) ;;
esac

command -v "${PROBE[0]}" >/dev/null 2>&1 || exit 1

"${PROBE[@]}" 2>/dev/null | grep -qE "(^|[[:space:]])${VERSION}([[:space:]]|\$)"
