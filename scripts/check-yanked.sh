#!/usr/bin/env bash
set -euo pipefail

# Refuse to proceed when the version about to be published is already yanked
# on crates.io. Pass --derive to check tightbeam-derive instead of tightbeam-rs.
#
# The registry is the only authority on yank state, so this asks the registry
# rather than a repository tag that a yank performed elsewhere never updates.
# A registry that cannot answer stops the release: scripts/crates-io.sh exits
# non-zero on every outcome short of a definite answer.

PACKAGE="tightbeam-rs"

for arg in "$@"; do
	if [ "$arg" = "--derive" ]; then
		PACKAGE="tightbeam-derive"
	fi
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$("$ROOT/scripts/crate-version.sh" "$PACKAGE")"
STATE="$("$ROOT/scripts/crates-io.sh" "$PACKAGE" "$VERSION")"

if [ "$STATE" = "yanked" ]; then
	printf '  \033[0;31m[error]\033[0m %s %s has been yanked. Cannot proceed.\n' "$PACKAGE" "$VERSION" >&2
	exit 1
fi

printf '  \033[0;32m[ok]\033[0m %s %s is %s on crates.io.\n' "$PACKAGE" "$VERSION" "$STATE"
